import type { PolicyModule, ReasonCode } from "../../types/policy.js";
import type { DecisionInput, DecisionComputationResult } from "./types.js";
import { deepMerge } from "../../utils/deepMerge.js";

/**
 * runDecisionModules — the explicit decision phase of the OxDeAI policy engine.
 *
 * Evaluates a set of policy modules against (intent + state) and returns a
 * deterministic ALLOW / DENY decision with accumulated post-policy state.
 *
 * Contract:
 *  - Pure: the input state is never mutated
 *  - Deterministic: identical inputs always produce identical outputs
 *  - No IO: no async, no external calls, no entropy
 *
 * Module evaluation semantics:
 *  - All modules are evaluated against the same pre-call working state.
 *    Modules do NOT see deltas from preceding modules during evaluation.
 *  - Results are processed in module-order.
 *  - ALLOW results whose stateDelta is non-null are deep-merged into the
 *    accumulating working state.
 *  - In fail-fast mode, delta accumulation stops at the first DENY result.
 *  - In collect-all mode, deny reasons are collected from every module.
 *
 * This function answers only:
 *   (intent + state + modules) → decision + reasons + nextState
 *
 * Authorization construction, audit emission, and state commit happen
 * in PolicyEngine.evaluatePure() after this phase returns.
 */
export function runDecisionModules(
  input:   DecisionInput,
  modules: readonly PolicyModule[],
): DecisionComputationResult {
  let working = input.state;
  const denyReasons: ReasonCode[] = [];

  // Evaluate all modules against the current working state.
  // All modules see the same pre-delta state — cumulative inter-module
  // delta propagation during evaluation is intentionally not supported.
  const results = modules.map((m) => m.evaluate(input.intent, working));

  // Process results in module-order: accumulate deltas on ALLOW,
  // collect reasons on DENY. In fail-fast mode, stop after the first DENY.
  for (const r of results) {
    if (r.decision === "DENY") {
      denyReasons.push(...r.reasons);
      if (input.mode === "fail-fast") break;
    } else if (r.stateDelta) {
      working = deepMerge(working, r.stateDelta);
    }
  }

  if (denyReasons.length > 0) {
    // DENY: no module deltas are applied — return the original input state
    return { decision: "DENY", reasons: denyReasons, nextState: input.state };
  }

  // ALLOW: return the accumulated state with all module deltas applied
  return { decision: "ALLOW", reasons: [], nextState: working };
}
