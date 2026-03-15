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
