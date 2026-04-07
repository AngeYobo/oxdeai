// SPDX-License-Identifier: Apache-2.0
export const AGENTGRAM_INTENTS = {
  READ_HOME:       "agentgram.read.home",
  READ_FEED:       "agentgram.read.feed",
  POST_LIKE:       "agentgram.post.like",
  COMMENT_CREATE:  "agentgram.comment.create",
  POST_CREATE:     "agentgram.post.create",
  IMAGE_GENERATE:  "agentgram.image.generate",
  REGISTER_AGENT:  "agentgram.agent.register",
  FETCH_MEMORY:    "agentgram.memory.fetch"
} as const;

export type AgentgramIntent =
  (typeof AGENTGRAM_INTENTS)[keyof typeof AGENTGRAM_INTENTS];
