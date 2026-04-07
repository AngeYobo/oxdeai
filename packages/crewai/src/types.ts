// SPDX-License-Identifier: Apache-2.0
import type { PolicyEngine, State } from "@oxdeai/core";
import type { OxDeAIGuardConfig } from "@oxdeai/guard";

/**
 * A CrewAI-style tool/action call.
 *
 * Structurally compatible with the tool call shape produced by CrewAI agents.
 * No import from the CrewAI library is required — attach OxDeAI fields
 * (`estimatedCost`, `resourceType`, `timestampSeconds`) when constructing
 * calls in your agent executor.
 */
export type CrewAIToolCall = {
  /** Tool name — matches the tool's registered name in the CrewAI crew. */
  name: string;
  /** Tool arguments — parsed key/value pairs passed to the tool. */
  args: Record<string, unknown>;
  /** Optional task or call identifier — used as `intent_id` when present. */
  id?: string;
  /** Estimated monetary cost in whole units (e.g. USD). Passed to the default normalizer as `estimatedCost`. */
  estimatedCost?: number;
  /** Resource type hint (e.g. `"gpu"`, `"payment"`). Used to infer `action_type` by the default normalizer. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to `Date.now() / 1000` when absent. */
  timestampSeconds?: number;
};

/**
 * Configuration for `createCrewAIGuard`.
 *
 * Extends `OxDeAIGuardConfig` with a required `agentId` field.
 * CrewAI tool calls do not carry agent identity — the adapter injects it
 * from this config into every `ProposedAction` it builds.
 */
export type CrewAIGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /** Load the current policy state. May be async. */
  getState: () => State | Promise<State>;
  /** Persist the next state after a successful execution. May be async. */
  setState: (state: State) => void | Promise<void>;

  /**
   * Identity of the acting agent. Injected as `context.agent_id` on every
   * `ProposedAction` derived from a tool call.
   */
  agentId: string;

  /**
   * Optional custom mapping from a `ProposedAction` (built from the tool call)
   * to an OxDeAI `Intent`. When omitted, the guard's default normalizer is used.
   *
   * The `ProposedAction` passed here always has:
   *   - `name`    from `toolCall.name`
   *   - `args`    from `toolCall.args`
   *   - `context.agent_id`   from `config.agentId`
   *   - `context.intent_id`  from `toolCall.id` (when present)
   *   - `estimatedCost`      from `toolCall.estimatedCost`
   *   - `resourceType`       from `toolCall.resourceType`
   *   - `timestampSeconds`   from `toolCall.timestampSeconds` (or now)
   */
  mapActionToIntent?: OxDeAIGuardConfig["mapActionToIntent"];

  /** Called after authorization succeeds but before the execute callback. */
  beforeExecute?: OxDeAIGuardConfig["beforeExecute"];

  /**
   * Audit hook fired after every decision (ALLOW and DENY).
   * Errors thrown here are swallowed.
   */
  onDecision?: OxDeAIGuardConfig["onDecision"];

  /** When true, missing optional normalizer fields cause hard failures. */
  strict?: boolean;
};

/**
 * The guard function returned by `createCrewAIGuard`.
 * Call it with a CrewAI tool call and the execute callback.
 */
export type CrewAIGuardFn = <T>(
  toolCall: CrewAIToolCall,
  execute: () => Promise<T>
) => Promise<T>;
