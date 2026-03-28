import { createGuard } from "@oxdeai/sdk";
import type {
  AuditAdapter,
  GuardResult,
  IntentBuilderInput,
  StateAdapter
} from "@oxdeai/sdk";
import type { PolicyEngine } from "@oxdeai/core";

import { AGENTGRAM_INTENTS } from "./intents.js";
import type { AgentgramAction } from "./types.js";

export interface AgentgramGuardConfig {
  engine: PolicyEngine;
  agentId: string;
  stateAdapter: StateAdapter;
  auditAdapter?: AuditAdapter;
}

function toTarget(action: AgentgramAction): string {
  switch (action.tool) {
    case AGENTGRAM_INTENTS.READ_HOME:
      return "agentgram:/home";
    case AGENTGRAM_INTENTS.READ_FEED:
      return "agentgram:/feed";
    case AGENTGRAM_INTENTS.POST_LIKE:
      return `agentgram:/posts/${action.postId}/like`;
    case AGENTGRAM_INTENTS.COMMENT_CREATE:
      return `agentgram:/posts/${action.postId}/comments`;
    case AGENTGRAM_INTENTS.REGISTER_AGENT:
      return "agentgram:/agents/register";
    case AGENTGRAM_INTENTS.FETCH_MEMORY:
      return `agentgram:/memories/${action.agentName}`;
    default: {
      const _exhaustive: never = action;
      throw new Error(`Unsupported action: ${String(_exhaustive)}`);
    }
  }
}

function toIntentInput(
  action: AgentgramAction,
  agentId: string
): IntentBuilderInput {
  return {
    intent_id: `agentgram-${action.tool}-${action.nonce.toString()}`,
    agent_id: agentId,
    action_type: "PROVISION",
    amount: 0n,
    target: toTarget(action),
    nonce: action.nonce,
    timestamp: action.timestampSeconds,
    tool: action.tool,
    tool_call: true,
    depth: 0
  };
}

export function createAgentgramGuard(config: AgentgramGuardConfig) {
  const guard = createGuard({
    engine: config.engine,
    stateAdapter: config.stateAdapter,
    auditAdapter: config.auditAdapter
  });

  return async function agentgramGuard<T>(
    action: AgentgramAction,
    execute: () => Promise<T>
  ): Promise<T> {
    const result: GuardResult<T> = await guard(
      toIntentInput(action, config.agentId),
      async () => execute()
    );

    if (result.output.decision === "DENY") {
      throw new Error(`DENY: ${result.output.reasons.join(", ")}`);
    }

    if (!result.executed) {
      throw new Error("DENY: execution was blocked");
    }

    return result.executionResult;
  };
}
