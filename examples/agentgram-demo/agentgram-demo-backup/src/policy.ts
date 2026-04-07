// SPDX-License-Identifier: Apache-2.0
import { AGENTGRAM_INTENTS } from "./intents.js";
import type { AgentgramIntent } from "./intents.js";
import type { AuthorizationDecision } from "./types.js";
import type { AgentgramPolicyState } from "./state.js";

function deny(reason: string, intent: string): AuthorizationDecision {
  return { verdict: "DENY", reason, intent: intent as AgentgramIntent };
}

function allow(intent: string): AuthorizationDecision {
  return { verdict: "ALLOW", reason: "ok", intent: intent as AgentgramIntent };
}

export function evaluatePolicy(
  intent: string,
  state: AgentgramPolicyState
): AuthorizationDecision {
  if (state.apiHost !== "agentgram-production.up.railway.app") {
    return deny("invalid_domain", intent);
  }

  if (!state.hasApiKey) {
    return deny("missing_api_key", intent);
  }

  switch (intent) {
    case AGENTGRAM_INTENTS.READ_HOME:
    case AGENTGRAM_INTENTS.READ_FEED:
      return allow(intent);

    case AGENTGRAM_INTENTS.POST_LIKE:
      return allow(intent);

    case AGENTGRAM_INTENTS.COMMENT_CREATE:
      if (!state.memoryFetchedForTarget) {
        return deny("missing_memory_context", intent);
      }
      if (!state.commentCooldownOk) {
        return deny("comment_cooldown", intent);
      }
      return allow(intent);

    case AGENTGRAM_INTENTS.POST_CREATE:
      if (!state.postCooldownOk) {
        return deny("post_cooldown", intent);
      }
      return allow(intent);

    case AGENTGRAM_INTENTS.IMAGE_GENERATE:
      if (
        state.imageGenerationsRemainingToday <= 0 &&
        !state.ownGeminiKeyEnabled
      ) {
        return deny("image_quota_exceeded", intent);
      }
      return allow(intent);

    default:
      return deny("unknown_intent", intent);
  }
}
