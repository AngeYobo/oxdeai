// SPDX-License-Identifier: Apache-2.0
import type { Authorization, Intent } from "@oxdeai/core";
import { verifyDelegationChain } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction, GuardDecisionRecord, GuardCallOptions } from "./types.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "./errors.js";

// ── validation ────────────────────────────────────────────────────────────────

function validateConfig(config: OxDeAIGuardConfig): void {
  if (!config || typeof config !== "object") {
    throw new OxDeAIGuardConfigurationError("config must be a plain object.");
  }
  if (!config.engine || typeof config.engine.evaluatePure !== "function") {
    throw new OxDeAIGuardConfigurationError("config.engine must be a PolicyEngine instance with an evaluatePure method.");
  }
  if (typeof config.getState !== "function") {
    throw new OxDeAIGuardConfigurationError("config.getState must be a function.");
  }
  if (typeof config.setState !== "function") {
    throw new OxDeAIGuardConfigurationError("config.setState must be a function.");
  }
}

// ── decision audit ────────────────────────────────────────────────────────────

async function fireDecision(
  onDecision: OxDeAIGuardConfig["onDecision"],
  record: GuardDecisionRecord
): Promise<void> {
  if (!onDecision) return;
  try {
    await onDecision(record);
  } catch {
    // Audit hook errors must never block execution or propagate to callers.
  }
}

// ── guard factory ─────────────────────────────────────────────────────────────

/**
 * OxDeAIGuard — Universal Policy Enforcement Point (PEP).
 *
 * Returns a reusable async guard function. Call it with a ProposedAction and
 * an execute callback. The guard will:
 *   1. Load current state.
 *   2. Normalize the action to an Intent.
 *   3. Evaluate policy via engine.evaluatePure().
 *   4. On DENY → throw OxDeAIDenyError (execute is never called).
 *   5. On ALLOW → verify the authorization artifact.
 *   6. Call optional beforeExecute hook.
 *   7. Invoke execute().
 *   8. Persist nextState.
 *   9. Fire onDecision audit hook.
 *  10. Return the execute() result.
 *
 * Delegation path (when opts.delegation is provided):
 *   1. Normalize the action to an Intent (scope amount check).
 *   2. Verify the DelegationV1 chain locally (no engine call).
 *   3. Check proposed action is within delegation scope (tools, max_amount).
 *   4. Call optional beforeExecute hook.
 *   5. Invoke execute().
 *   6. Fire onDecision audit hook. setState is NOT called.
 *   7. Return the execute() result.
 *
 * Security invariants:
 *   - ALLOW without authorization → OxDeAIAuthorizationError (no execution).
 *   - ALLOW without nextState     → OxDeAIAuthorizationError (no execution).
 *   - verifyAuthorization failure → OxDeAIAuthorizationError (no execution).
 *   - Delegation chain failure    → OxDeAIDelegationError (no execution).
 *   - Scope violation             → OxDeAIDelegationError (no execution).
 *   - Normalization failure       → OxDeAINormalizationError (no execution).
 *   - Evaluation / state errors   → re-thrown (fail-closed).
 */
export function OxDeAIGuard(config: OxDeAIGuardConfig) {
  validateConfig(config);

  const normalize: (action: ProposedAction) => Intent =
    config.mapActionToIntent ?? defaultNormalizeAction;

  return async function guard(
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts?: GuardCallOptions
  ): Promise<unknown> {
    // ── 1. Load state ──────────────────────────────────────────────────────
    const state = await config.getState();

    // ── 2. Normalize action → intent ───────────────────────────────────────
    let intent: Intent;
    try {
      intent = normalize(action);
    } catch (err) {
      if (err instanceof OxDeAINormalizationError) throw err;
      // Custom mapActionToIntent threw something unexpected — fail closed.
      throw new OxDeAINormalizationError(
        `mapActionToIntent threw an unexpected error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // ── 3. Delegation path ─────────────────────────────────────────────────
    if (opts?.delegation) {
      const { delegation, parentAuth } = opts.delegation;

      if (!delegation || !parentAuth) {
        throw new OxDeAIAuthorizationError(
          "Delegation input is incomplete: both delegation and parentAuth are required. Execution blocked."
        );
      }

      const now = intent.timestamp;
      const violationMessages: string[] = [];

      // Verify delegation chain:
      //   - parent hash binding
      //   - parent expiry
      //   - delegator === parent.audience
      //   - policy_id binding
      //   - delegation expiry <= parent expiry
      //   - delegation expiry
      //   - delegation signature (if trustedKeySets provided)
      //   - scope narrowing against parent is NOT checked here (parentScope
      //     is the deployer's responsibility when constructing the delegation)
      const chainResult = verifyDelegationChain(delegation, parentAuth, {
        now,
        trustedKeySets: config.trustedKeySets,
        requireSignatureVerification: config.requireDelegationSignatureVerification ?? false,
        consumedDelegationIds: config.consumedDelegationIds,
      });

      if (!chainResult.ok) {
        for (const v of chainResult.violations) {
          violationMessages.push(v.message ?? v.code);
        }
      }

      // Guard-level scope enforcement: is the proposed action within
      // the delegation's declared scope?
      if (delegation.scope.tools !== undefined && !delegation.scope.tools.includes(action.name)) {
        violationMessages.push(
          `action "${action.name}" is not permitted by delegation scope.tools [${delegation.scope.tools.join(", ")}]`
        );
      }

      if (delegation.scope.max_amount !== undefined && intent.amount > delegation.scope.max_amount) {
        violationMessages.push(
          `intent amount ${intent.amount} exceeds delegation scope.max_amount ${delegation.scope.max_amount}`
        );
      }

      if (violationMessages.length > 0) {
        throw new OxDeAIDelegationError(violationMessages);
      }

      // parentAuth is AuthorizationV1; cast to Authorization for hook/audit
      // compatibility. Legacy fields will be absent — callers on the delegation
      // path should treat the value as AuthorizationV1 shape only.
      const parentAuthCompat = parentAuth as unknown as Authorization;

      // ── Delegation: beforeExecute hook ────────────────────────────────
      if (config.beforeExecute) {
        await config.beforeExecute(action, parentAuthCompat);
      }

      // ── Delegation: execute ───────────────────────────────────────────
      const result = await execute();

      // ── Delegation: audit hook (no setState — parent state is authoritative) ──
      await fireDecision(config.onDecision, {
        action,
        decision: "ALLOW",
        authorization: parentAuthCompat,
        delegation,
      });

      return result;
    }

    // ── 4. Standard path: evaluate policy ─────────────────────────────────
    let evalResult: ReturnType<typeof config.engine.evaluatePure>;
    try {
      evalResult = config.engine.evaluatePure(intent, state);
    } catch (err) {
      // Engine errors are never swallowed — callers must handle them.
      throw new OxDeAIAuthorizationError(
        `PolicyEngine.evaluatePure threw: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // ── 5. DENY path ───────────────────────────────────────────────────────
    if (evalResult.decision === "DENY") {
      const reasons = evalResult.reasons.map(String);
      await fireDecision(config.onDecision, {
        action,
        decision: "DENY",
        reasons,
      });
      throw new OxDeAIDenyError(reasons);
    }

    // ── 6. ALLOW: require authorization artifact and nextState ─────────────
    if (!evalResult.authorization) {
      throw new OxDeAIAuthorizationError(
        "PolicyEngine returned ALLOW without an authorization artifact. Execution blocked."
      );
    }
    if (!evalResult.nextState) {
      throw new OxDeAIAuthorizationError(
        "PolicyEngine returned ALLOW without a nextState. Execution blocked."
      );
    }

    const { authorization, nextState } = evalResult;

    // ── 6b. Verify the authorization artifact ──────────────────────────────
    const now = intent.timestamp;
    const authCheck = config.engine.verifyAuthorization(intent, authorization, nextState, now);
    if (!authCheck.valid) {
      throw new OxDeAIAuthorizationError(
        `Authorization verification failed: ${authCheck.reason ?? "unknown reason"}. Execution blocked.`
      );
    }

    // ── 7. beforeExecute hook ──────────────────────────────────────────────
    if (config.beforeExecute) {
      await config.beforeExecute(action, authorization);
    }

    // ── 8. Execute the side effect ─────────────────────────────────────────
    const result = await execute();

    // ── 9. Persist nextState ───────────────────────────────────────────────
    await config.setState(nextState);

    // ── 10. Fire audit hook ────────────────────────────────────────────────
    await fireDecision(config.onDecision, {
      action,
      decision: "ALLOW",
      authorization,
    });

    // ── 11. Return result ──────────────────────────────────────────────────
    return result;
  };
}
