import type { Authorization, Intent, PolicyEngine, State } from "@oxdeai/core";

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

/** Structured record of the guard's decision, passed to the onDecision hook. */
export type GuardDecisionRecord = {
  action: ProposedAction;
  decision: "ALLOW" | "DENY";
  authorization?: Authorization;
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
};
