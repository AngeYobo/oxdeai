// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
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

test("ALLOW read home", () => {
  assert.equal(evaluatePolicy(AGENTGRAM_INTENTS.READ_HOME, base).verdict, "ALLOW");
});

test("ALLOW read feed", () => {
  assert.equal(evaluatePolicy(AGENTGRAM_INTENTS.READ_FEED, base).verdict, "ALLOW");
});

test("ALLOW like post", () => {
  assert.equal(evaluatePolicy(AGENTGRAM_INTENTS.POST_LIKE, base).verdict, "ALLOW");
});

test("DENY comment without memory context", () => {
  const d = evaluatePolicy(AGENTGRAM_INTENTS.COMMENT_CREATE, base);
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "missing_memory_context");
});

test("ALLOW comment with memory context", () => {
  assert.equal(
    evaluatePolicy(AGENTGRAM_INTENTS.COMMENT_CREATE, { ...base, memoryFetchedForTarget: true }).verdict,
    "ALLOW"
  );
});

test("ALLOW generate image", () => {
  assert.equal(evaluatePolicy(AGENTGRAM_INTENTS.IMAGE_GENERATE, base).verdict, "ALLOW");
});

test("DENY wrong domain", () => {
  const d = evaluatePolicy(AGENTGRAM_INTENTS.READ_HOME, { ...base, apiHost: "evil.example.com" });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "invalid_domain");
});

test("DENY missing api key", () => {
  const d = evaluatePolicy(AGENTGRAM_INTENTS.READ_HOME, { ...base, hasApiKey: false });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "missing_api_key");
});

test("DENY image quota exceeded", () => {
  const d = evaluatePolicy(AGENTGRAM_INTENTS.IMAGE_GENERATE, {
    ...base,
    imageGenerationsRemainingToday: 0,
    ownGeminiKeyEnabled: false,
  });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "image_quota_exceeded");
});

test("DENY unknown intent", () => {
  const d = evaluatePolicy("agentgram.unknown.action", base);
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "unknown_intent");
});
