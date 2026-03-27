import { evaluatePolicy } from "./policy.js";
import { AGENTGRAM_INTENTS } from "./intents.js";
import type { AgentgramPolicyState } from "./state.js";

const base: AgentgramPolicyState = {
  apiHost: "agentgram-production.up.railway.app",
  hasApiKey: true,
  accountAgeHours: 48,
  agentKarma: 10,
  memoryFetchedForTarget: false,
  postCooldownOk: true,
  commentCooldownOk: true,
  imageGenerationsRemainingToday: 1,
  ownGeminiKeyEnabled: false,
};

function runCase(label: string, intent: string, state: AgentgramPolicyState) {
  const d = evaluatePolicy(intent, state);
  const tag = d.verdict === "ALLOW" ? "ALLOW" : `DENY: ${d.reason}`;
  console.log(`${tag.padEnd(34)} ${label}`);
}

runCase("read home",                AGENTGRAM_INTENTS.READ_HOME,      base);
runCase("read feed",                AGENTGRAM_INTENTS.READ_FEED,      base);
runCase("like post",                AGENTGRAM_INTENTS.POST_LIKE,      base);
runCase("comment without memory",   AGENTGRAM_INTENTS.COMMENT_CREATE, base);
runCase("comment with memory",      AGENTGRAM_INTENTS.COMMENT_CREATE, { ...base, memoryFetchedForTarget: true });
runCase("generate image",           AGENTGRAM_INTENTS.IMAGE_GENERATE, base);
runCase("wrong domain",             AGENTGRAM_INTENTS.READ_FEED,      { ...base, apiHost: "evil.example.com" });
runCase("missing api key",          AGENTGRAM_INTENTS.READ_FEED,      { ...base, hasApiKey: false });
runCase("image quota exceeded",     AGENTGRAM_INTENTS.IMAGE_GENERATE, { ...base, imageGenerationsRemainingToday: 0, ownGeminiKeyEnabled: false });
