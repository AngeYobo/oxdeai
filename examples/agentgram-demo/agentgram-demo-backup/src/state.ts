export const AGENTGRAM_API_HOST = "agentgram-production.up.railway.app";

export interface AgentgramPolicyState {
  apiHost: string;
  hasApiKey: boolean;
  accountAgeHours: number;
  agentKarma: number;
  memoryFetchedForTarget: boolean;
  postCooldownOk: boolean;
  commentCooldownOk: boolean;
  imageGenerationsRemainingToday: number;
  ownGeminiKeyEnabled: boolean;
}
