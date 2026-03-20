import type { Authorization, AuthorizationV1, DelegationV1, Intent, KeySet, PolicyEngine, State } from "@oxdeai/core";

/**
 * A runtime-agnostic description of an action an agent wants to perform.
 * Runtimes map their tool-call or action objects to this type before
 * passing them to the guard.
 */
export type ProposedAction = {
  /** Name of the action / tool being invoked (e.g. "provision_gpu"). */
  name: string;
  /** Arguments passed to the action. */
  args: Record<string, unknown>;
  /** Optional ambient context — agent_id and target are read from here by the default normalizer. */
  context?: Record<string, unknown>;
  /** Estimated monetary cost of the action in whole units (e.g. USD). Used to set the intent amount. */
  estimatedCost?: number;
  /** Resource category (e.g. "gpu", "payment"). Used to infer action_type. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to Date.now() / 1000 when omitted. */
  timestampSeconds?: number;
};

/**
 * Delegation credentials presented by a child agent to execute within a
 * delegated scope. The guard verifies the full chain before execution.
 */
export type GuardDelegationInput = {
  /** The DelegationV1 artifact issued by the parent agent. */
  delegation: DelegationV1;
  /** The parent AuthorizationV1 that the delegation was derived from. */
  parentAuth: AuthorizationV1;
};

/**
 * Per-call options passed as the optional third argument to the guard function.
 * When `delegation` is present, the guard takes the delegation verification path
 * instead of the standard policy-evaluation path.
 */
export type GuardCallOptions = {
  /**
   * Delegation credentials for child-agent execution.
   * When provided, the guard skips engine.evaluatePure() and instead
   * verifies the delegation chain locally.
   */
  delegation?: GuardDelegationInput;
};

/** Structured record of the guard's decision, passed to the onDecision hook. */
export type GuardDecisionRecord = {
  action: ProposedAction;
  decision: "ALLOW" | "DENY";
  authorization?: Authorization;
  /** Present when the decision was made via the delegation verification path. */
  delegation?: DelegationV1;
  reasons?: string[];
};

/** Configuration for OxDeAIGuard. */
export type OxDeAIGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /** Load the current policy state. May be async. */
  getState: () => State | Promise<State>;
  /** Persist the next state after a successful execution. May be async. */
  setState: (state: State) => void | Promise<void>;

  /**
   * Optional custom mapping from a ProposedAction to an OxDeAI Intent.
   * When omitted, the default normalizer is used.
   */
  mapActionToIntent?: (action: ProposedAction) => Intent;

  /**
   * Optional hook called after authorization succeeds but before the
   * side-effecting execute() callback is invoked.
   */
  beforeExecute?: (
    action: ProposedAction,
    authorization: Authorization
  ) => void | Promise<void>;

  /**
   * Optional audit hook called after every decision (ALLOW and DENY).
   * Errors thrown here are swallowed so they cannot block execution.
   */
  onDecision?: (result: GuardDecisionRecord) => void | Promise<void>;

  /**
   * When true, missing optional fields that can be defaulted will instead
   * cause a hard failure. Defaults to false.
   */
  strict?: boolean;

  /**
   * KeySets used to verify Ed25519 signatures on DelegationV1 artifacts.
   * When absent, signature verification is skipped (unless
   * requireDelegationSignatureVerification is true, which will fail-closed).
   */
  trustedKeySets?: KeySet | readonly KeySet[];

  /**
   * When true, the guard fails closed if no trustedKeySets are provided
   * for delegation path verification. Defaults to false.
   */
  requireDelegationSignatureVerification?: boolean;

  /**
   * Set of delegation_ids already consumed in this session.
   * Used for replay protection on the delegation path.
   * Tracking across calls is the caller's responsibility.
   */
  consumedDelegationIds?: readonly string[];
};
