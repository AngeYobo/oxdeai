import { evaluatePolicy } from "./policy.js";
import { AGENTGRAM_INTENTS } from "./intents.js";

import type { AgentgramPolicyState } from "./state.js";
import type {
  AgentgramActionInput,
  AuthorizationDecision
} from "./types.js";
import type { AgentgramIntent } from "./intents.js";

export interface AdapterConfig {
  apiKey: string;
}

export interface PolicyRequest {
  intent: AgentgramIntent;
  state: AgentgramPolicyState;
}

export type PolicyEvaluator = (
  req: PolicyRequest
) => Promise<AuthorizationDecision>;

function buildPolicyRequest(
  intent: AgentgramIntent,
  state: AgentgramPolicyState
): PolicyRequest {
  return { intent, state };
}

const localEvaluate: PolicyEvaluator = (req) =>
  Promise.resolve(evaluatePolicy(req.intent, req.state));

function requireInput(
  intent: AgentgramIntent,
  input: AgentgramActionInput
): void {
  if (intent === AGENTGRAM_INTENTS.POST_LIKE && !input.postId) {
    throw new Error("missing postId");
  }

  if (
    intent === AGENTGRAM_INTENTS.COMMENT_CREATE &&
    (!input.postId || !input.content)
  ) {
    throw new Error("missing comment input");
  }

  if (intent === AGENTGRAM_INTENTS.IMAGE_GENERATE && !input.prompt) {
    throw new Error("missing prompt");
  }
}

export async function executeAgentgramAction(
  intent: AgentgramIntent,
  input: AgentgramActionInput,
  state: AgentgramPolicyState,
  config: AdapterConfig,
  evaluate: PolicyEvaluator = localEvaluate
) {
  const decision = await evaluate(buildPolicyRequest(intent, state));

  if (decision.verdict === "DENY") {
    throw new Error(`DENY: ${decision.reason}`);
  }

  requireInput(intent, input);

  // Execution boundary starts here
  const client = await import("./client.js");

  switch (intent) {
    case AGENTGRAM_INTENTS.READ_HOME:
      return client.getHome({ apiKey: config.apiKey });

    case AGENTGRAM_INTENTS.READ_FEED:
      return client.getFeed({ apiKey: config.apiKey });

    case AGENTGRAM_INTENTS.POST_LIKE:
      return client.likePost({ apiKey: config.apiKey }, input.postId!);

    case AGENTGRAM_INTENTS.COMMENT_CREATE:
      return client.commentOnPost(
        { apiKey: config.apiKey },
        input.postId!,
        input.content!
      );

    case AGENTGRAM_INTENTS.POST_CREATE:
      return client.createPost(
        { apiKey: config.apiKey },
        {
          imageUrl: input.imageUrl,
          prompt: input.prompt,
          caption: input.content
        }
      );

    case AGENTGRAM_INTENTS.IMAGE_GENERATE:
      return client.generateImage({ apiKey: config.apiKey }, input.prompt!);

    default:
      throw new Error("unknown intent");
  }
}