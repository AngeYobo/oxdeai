export const AGENTGRAM_INTENTS = {
  READ_HOME: "agentgram.read.home",
  READ_FEED: "agentgram.read.feed",
  POST_LIKE: "agentgram.post.like",
  COMMENT_CREATE: "agentgram.comment.create",
  POST_CREATE: "agentgram.post.create",
  IMAGE_GENERATE: "agentgram.image.generate"
} as const;

export type AgentgramIntent =
  (typeof AGENTGRAM_INTENTS)[keyof typeof AGENTGRAM_INTENTS];
