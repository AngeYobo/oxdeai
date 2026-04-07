// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { ReasonCode } from "../../types/policy.js";

/**
 * Input to the decision phase.
 *
 * Contains only what is needed to make a deterministic authorization
 * decision: the proposed intent, the current policy state, and the
 * evaluation mode. No external IO or entropy is required.
 */
export interface DecisionInput {
  intent: Intent;
  state:  State;
  mode:   "fail-fast" | "collect-all";
}

/**
 * Result of the decision phase — the output of
 *   (intent + state + module policies) → ALLOW | DENY
 *
 * On ALLOW:  nextState carries all module deltas applied in-order.
 *            Used downstream for authorization binding and state commit.
 *
 * On DENY:   nextState is the original input state (no deltas applied).
 *            reasons carries one or more denial codes in module-order.
 *
 * Authorization construction, audit emission, and state persistence are
 * NOT part of this result. This represents the pure decision boundary.
 */
export type DecisionComputationResult =
  | { decision: "ALLOW"; reasons: [];           nextState: State }
  | { decision: "DENY";  reasons: ReasonCode[]; nextState: State };
