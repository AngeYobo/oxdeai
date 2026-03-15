import type { Intent } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction, GuardDecisionRecord } from "./types.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
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
 * Security invariants:
 *   - ALLOW without authorization → OxDeAIAuthorizationError (no execution).
 *   - ALLOW without nextState     → OxDeAIAuthorizationError (no execution).
 *   - verifyAuthorization failure → OxDeAIAuthorizationError (no execution).
 *   - Normalization failure       → OxDeAINormalizationError (no execution).
 *   - Evaluation / state errors   → re-thrown (fail-closed).
 */
export function OxDeAIGuard(config: OxDeAIGuardConfig) {
  validateConfig(config);

  const normalize: (action: ProposedAction) => Intent =
    config.mapActionToIntent ?? defaultNormalizeAction;

  return async function guard(
    action: ProposedAction,
    execute: () => Promise<unknown>
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

    // ── 3. Evaluate policy ─────────────────────────────────────────────────
    let evalResult: ReturnType<typeof config.engine.evaluatePure>;
    try {
      evalResult = config.engine.evaluatePure(intent, state);
    } catch (err) {
      // Engine errors are never swallowed — callers must handle them.
      throw new OxDeAIAuthorizationError(
        `PolicyEngine.evaluatePure threw: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // ── 4. DENY path ───────────────────────────────────────────────────────
    if (evalResult.decision === "DENY") {
      const reasons = evalResult.reasons.map(String);
      await fireDecision(config.onDecision, {
        action,
        decision: "DENY",
        reasons,
      });
      throw new OxDeAIDenyError(reasons);
    }

    // ── 5. ALLOW: require authorization artifact and nextState ─────────────
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

    // ── 5b. Verify the authorization artifact ──────────────────────────────
    const now = intent.timestamp;
    const authCheck = config.engine.verifyAuthorization(intent, authorization, nextState, now);
    if (!authCheck.valid) {
      throw new OxDeAIAuthorizationError(
        `Authorization verification failed: ${authCheck.reason ?? "unknown reason"}. Execution blocked.`
      );
    }

    // ── 6. beforeExecute hook ──────────────────────────────────────────────
    if (config.beforeExecute) {
      await config.beforeExecute(action, authorization);
    }

    // ── 7. Execute the side effect ─────────────────────────────────────────
    const result = await execute();

    // ── 8. Persist nextState ───────────────────────────────────────────────
    await config.setState(nextState);

    // ── 9. Fire audit hook ─────────────────────────────────────────────────
    await fireDecision(config.onDecision, {
      action,
      decision: "ALLOW",
      authorization,
    });

    // ── 10. Return result ──────────────────────────────────────────────────
    return result;
  };
}
