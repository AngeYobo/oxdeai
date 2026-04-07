// SPDX-License-Identifier: Apache-2.0
import type { PolicyEngine, State } from "@oxdeai/core";
import type { OxDeAIGuardConfig } from "@oxdeai/guard";

/**
 * An OpenClaw action/skill call.
 *
 * Structurally compatible with the action shape produced by the OpenClaw
 * runtime (workflow planner → action dispatcher). No import from the OpenClaw
 * library is required.
 *
 * OpenClaw-specific fields:
 *   - `workflow_id`  identifies the parent workflow (carried as context)
 *   - `step_id`      identifies this step within the workflow - used as `intent_id`
 */
export type OpenClawAction = {
  /** Skill or tool name dispatched by the OpenClaw action dispatcher. */
  name: string;
  /** Action arguments - parsed key/value pairs from the workflow step. */
  args: Record<string, unknown>;
  /** Step identifier within the workflow - used as `intent_id` when present. */
  step_id?: string;
  /** Parent workflow identifier - carried in `context.workflow_id` when present. */
  workflow_id?: string;
  /** Estimated monetary cost in whole units (e.g. USD). Passed to the default normalizer as `estimatedCost`. */
  estimatedCost?: number;
  /** Resource type hint (e.g. `"gpu"`, `"payment"`). Used to infer `action_type` by the default normalizer. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to `Date.now() / 1000` when absent. */
  timestampSeconds?: number;
};

/**
 * Configuration for `createOpenClawGuard`.
 *
 * Extends `OxDeAIGuardConfig` with a required `agentId` field.
 * OpenClaw action calls do not carry agent identity - the adapter injects it
 * from this config into every `ProposedAction` it builds.
 */
export type OpenClawGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /** Load the current policy state. May be async. */
  getState: () => State | Promise<State>;
  /** Persist the next state after a successful execution. May be async. */
  setState: (state: State) => void | Promise<void>;

  /**
   * Identity of the acting agent. Injected as `context.agent_id` on every
   * `ProposedAction` derived from an action call.
   */
  agentId: string;

  /**
   * Optional custom mapping from a `ProposedAction` (built from the action call)
   * to an OxDeAI `Intent`. When omitted, the guard's default normalizer is used.
   *
   * The `ProposedAction` passed here always has:
   *   - `name`    from `action.name`
   *   - `args`    from `action.args`
   *   - `context.agent_id`    from `config.agentId`
   *   - `context.intent_id`   from `action.step_id` (when present)
   *   - `context.workflow_id` from `action.workflow_id` (when present)
   *   - `estimatedCost`       from `action.estimatedCost`
   *   - `resourceType`        from `action.resourceType`
   *   - `timestampSeconds`    from `action.timestampSeconds` (or now)
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
 * The guard function returned by `createOpenClawGuard`.
 * Call it with an OpenClaw action and the execute callback.
 */
export type OpenClawGuardFn = <T>(
  action: OpenClawAction,
  execute: () => Promise<T>
) => Promise<T>;
