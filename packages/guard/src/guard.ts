// SPDX-License-Identifier: Apache-2.0
import type { Authorization, AuthorizationV1, Intent, KeySet } from "@oxdeai/core";
import { verifyDelegationChain, verifyAuthorization as strictVerifyAuthorization } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction, GuardDecisionRecord, GuardCallOptions } from "./types.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import { createInMemoryReplayStore } from "./replayStore.js";
import type { ReplayStore } from "./replayStore.js";
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
  if (typeof config.expectedAudience !== "string" || config.expectedAudience.length === 0) {
    throw new OxDeAIGuardConfigurationError(
      "config.expectedAudience is required and must be a non-empty string. " +
      "Set it to the agent identity this guard instance protects (matches authorization_audience in PolicyEngine)."
    );
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
  const trustedKeySets: readonly KeySet[] | undefined = config.trustedKeySets
    ? Array.isArray(config.trustedKeySets)
      ? config.trustedKeySets
      : [config.trustedKeySets]
    : undefined;

  if (!trustedKeySets || trustedKeySets.length === 0) {
    throw new OxDeAIGuardConfigurationError(
      "trustedKeySets are required for authorization verification and must not be empty."
    );
  }

  // Pluggable replay store. Defaults to in-memory (single-process semantics).
  // Replace with a durable backend for multi-process / restart-durable deployments.
  const replayStore: ReplayStore = config.replayStore ?? createInMemoryReplayStore();

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

      const now = Math.floor(Date.now() / 1000);
      const violationMessages: string[] = [];

      // Atomically check-and-consume the delegation_id. Fail closed on store errors.
      let delegConsumed: boolean;
      try {
        delegConsumed = replayStore.consumeDelegationId
          ? await replayStore.consumeDelegationId(delegation.delegation_id, { expiry: delegation.expiry })
          : true;
      } catch (err) {
        throw new OxDeAIAuthorizationError(
          `Replay store unavailable for delegation_id: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
        );
      }
      if (!delegConsumed) {
        throw new OxDeAIAuthorizationError("Delegation replay detected. Execution blocked.");
      }

      // Verify delegation chain:
      //   - parent hash binding
      //   - parent expiry
      //   - delegator === parent.audience
      //   - policy_id binding
      //   - delegation expiry <= parent expiry
      //   - delegation expiry
      //   - delegation signature (if trustedKeySets provided)
      //   - scope narrowing against parent (enforced via parentScope)
      //
      // Derive parentScope from parentAuth; if not present, fail closed.
      const parentScope = (parentAuth as any).scope;
      if (!parentScope) {
        throw new OxDeAIAuthorizationError(
          "Parent authorization scope is required for delegation narrowing but was not provided. Execution blocked."
        );
      }

      const chainResult = verifyDelegationChain(delegation, parentAuth, {
        now,
        trustedKeySets: config.trustedKeySets,
        requireSignatureVerification: true,
        parentScope,
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

      // Require scope presence for narrowing; fail closed if absent.
      if (!delegation.scope) {
        violationMessages.push("delegation.scope is required for narrowing; execution blocked.");
      }

      if (violationMessages.length > 0) {
        throw new OxDeAIDelegationError(violationMessages);
      }

      // Enforce strict verification on the parent Authorization as well.
      // Atomically check-and-consume the parentAuth auth_id. Fail closed on store errors.
      let parentAuthConsumed: boolean;
      try {
        parentAuthConsumed = await replayStore.consumeAuthId(
          parentAuth.auth_id, { expiry: parentAuth.expiry }
        );
      } catch (err) {
        throw new OxDeAIAuthorizationError(
          `Replay store unavailable for parentAuth auth_id: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
        );
      }
      if (!parentAuthConsumed) {
        throw new OxDeAIAuthorizationError(
          "Authorization replay detected on parentAuth: auth_id already consumed. Execution blocked."
        );
      }

      const parentAuthResult = strictVerifyAuthorization(parentAuth as AuthorizationV1, {
        now,
        mode: "strict",
        trustedKeySets,
        requireSignatureVerification: true,
        expectedPolicyId: parentAuth.policy_id,
        expectedAudience: config.expectedAudience,
        expectedIssuer: parentAuth.issuer,
      });

      if (parentAuthResult.status !== "ok") {
        const reasons =
          parentAuthResult.violations?.map((v) => v.code).join(", ") ||
          parentAuthResult.status ||
          "unknown reason";
        throw new OxDeAIAuthorizationError(`Parent authorization verification failed: ${reasons}. Execution blocked.`);
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

    // ── 6b. Verify the authorization artifact (strict verifier, fail-closed) ─
    const now = Math.floor(Date.now() / 1000);

    // Atomically check-and-consume the auth_id before execution. Fail closed on store errors.
    let authConsumed: boolean;
    try {
      authConsumed = await replayStore.consumeAuthId(
        authorization.auth_id, { expiry: (authorization as AuthorizationV1).expiry ?? 0 }
      );
    } catch (err) {
      throw new OxDeAIAuthorizationError(
        `Replay store unavailable: ${err instanceof Error ? err.message : String(err)}. Execution blocked.`
      );
    }
    if (!authConsumed) {
      throw new OxDeAIAuthorizationError("Authorization replay detected: auth_id already consumed. Execution blocked.");
    }

    const authResult = strictVerifyAuthorization(authorization as AuthorizationV1, {
      now,
      mode: "strict",
      trustedKeySets,
      requireSignatureVerification: true,
      expectedPolicyId: authorization.policy_id,
      expectedAudience: config.expectedAudience,
      expectedIssuer: authorization.issuer,
    });

    if (authResult.status !== "ok") {
      const reasons =
        authResult.violations?.map((v) => v.code).join(", ") || authResult.status || "unknown reason";
      throw new OxDeAIAuthorizationError(`Authorization verification failed: ${reasons}. Execution blocked.`);
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
