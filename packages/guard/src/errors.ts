// SPDX-License-Identifier: Apache-2.0
/**
 * Thrown when the policy engine returns a DENY decision.
 * Execution is blocked; inspect `reasons` for policy violations.
 */
export class OxDeAIDenyError extends Error {
  readonly reasons: readonly string[];

  constructor(reasons: readonly string[]) {
    super(`OxDeAI guard denied execution: [${reasons.join(", ")}]`);
    this.name = "OxDeAIDenyError";
    this.reasons = Object.freeze([...reasons]);
  }
}

/**
 * Thrown when authorization is missing, malformed, or fails verification.
 * This is a hard security boundary — execution must not proceed.
 */
export class OxDeAIAuthorizationError extends Error {
  constructor(message: string) {
    super(`OxDeAI authorization error: ${message}`);
    this.name = "OxDeAIAuthorizationError";
  }
}

/**
 * Thrown when OxDeAIGuard is misconfigured (e.g. required engine fields absent).
 * Indicates a programming error in the adapter or caller.
 */
export class OxDeAIGuardConfigurationError extends Error {
  constructor(message: string) {
    super(`OxDeAI guard configuration error: ${message}`);
    this.name = "OxDeAIGuardConfigurationError";
  }
}

/**
 * Thrown when the default normalizer cannot convert a ProposedAction to an Intent.
 * Fail-closed: ambiguous or incomplete actions must not reach the engine.
 */
export class OxDeAINormalizationError extends Error {
  constructor(message: string) {
    super(`OxDeAI normalization error: ${message}`);
    this.name = "OxDeAINormalizationError";
  }
}

/**
 * Thrown when a compare-and-set (CAS) state commit fails because the persisted
 * version no longer matches the version read at evaluation time. This indicates
 * a concurrent modification — another request updated state between this guard's
 * getState() and setState() calls.
 *
 * Execution is blocked and no side effects are committed.
 * Extends OxDeAIAuthorizationError so existing catch blocks remain valid.
 */
export class OxDeAIConflictError extends OxDeAIAuthorizationError {
  constructor(message: string) {
    super(message);
    this.name = "OxDeAIConflictError";
  }
}

/**
 * Thrown when DelegationV1 verification fails at the guard boundary.
 * Extends OxDeAIAuthorizationError so existing catch blocks remain valid.
 * The `violations` field carries structured delegation-specific failure codes.
 *
 * Common violation codes:
 *   DELEGATION_SIGNATURE_INVALID  — Ed25519 signature check failed
 *   DELEGATION_PARENT_HASH_MISMATCH — parentAuth hash does not match
 *   DELEGATION_SCOPE_VIOLATION    — child scope exceeds parent scope
 *   DELEGATION_EXPIRED            — delegation has expired
 *   DELEGATION_AUDIENCE_MISMATCH  — delegatee does not match expectedDelegatee
 *   DELEGATION_MULTIHOP_DENIED    — parent is itself a DelegationV1
 */
export class OxDeAIDelegationError extends OxDeAIAuthorizationError {
  readonly violations: readonly string[];

  constructor(violations: readonly string[]) {
    super(`Delegation verification failed: [${violations.join(", ")}]. Execution blocked.`);
    this.name = "OxDeAIDelegationError";
    this.violations = Object.freeze([...violations]);
  }
}
