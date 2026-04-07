// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { intentHash } from "../crypto/hashes.js";
import type { Intent } from "../types/intent.js";

function baseIntent(): Intent {
  return {
    intent_id: "intent-1",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: 100n,
    target: "merchant-1",
    timestamp: 1730000000,
    metadata_hash: "0".repeat(64),
    nonce: 42n,
    signature: "sig",
    type: "EXECUTE",
    depth: 0,
    tool_call: true,
    tool: "openai.responses"
  };
}

test("intentHash ignores signature", () => {
  const a = baseIntent();
  const b = { ...a, signature: "another-sig" };
  assert.equal(intentHash(a), intentHash(b));
});

test("intentHash ignores unknown non-binding fields", () => {
  const a = baseIntent();
  const b = { ...a, _internal_trace_id: "trace-123" } as Intent & { _internal_trace_id: string };
  assert.equal(intentHash(a), intentHash(b as Intent));
});
