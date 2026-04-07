// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { ReplayEngine } from "../replay/ReplayEngine.js";
import type { AuditEntry } from "../audit/AuditLog.js";

function validEvents(policyId = "policy-A"): AuditEntry[] {
  return [
    {
      type: "INTENT_RECEIVED",
      intent_hash: "ih-1",
      agent_id: "agent-1",
      timestamp: 100,
      policyId
    },
    {
      type: "DECISION",
      intent_hash: "ih-1",
      decision: "ALLOW",
      reasons: [],
      policy_version: "v0.6",
      timestamp: 100,
      policyId
    },
    {
      type: "AUTH_EMITTED",
      authorization_id: "auth-1",
      intent_hash: "ih-1",
      expires_at: 160,
      timestamp: 101,
      policyId
    }
  ];
}

test("strict mode returns inconclusive for valid events without state anchor", () => {
  const out = ReplayEngine.verify(validEvents());
  assert.equal(out.ok, false);
  assert.equal(out.status, "inconclusive");
  assert.ok(out.auditHeadHash);
  assert.equal(out.violations.length, 1);
  assert.equal(out.violations[0].code, "NO_STATE_ANCHOR");
});

test("best-effort mode returns ok for valid events", () => {
  const out = ReplayEngine.verify(validEvents(), { mode: "best-effort" });
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
  assert.ok(out.auditHeadHash);
});

test("mixed policyId returns violation", () => {
  const events = validEvents();
  events[2] = { ...events[2], policyId: "policy-B" };

  const out = ReplayEngine.verify(events, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "violation");
  assert.ok(out.violations.some((v) => v.code === "MIXED_POLICY_ID"));
});

test("policyId mismatch against opts returns violation", () => {
  const out = ReplayEngine.verify(validEvents("policy-A"), {
    mode: "best-effort",
    policyId: "policy-Z"
  });

  assert.equal(out.ok, false);
  assert.equal(out.status, "violation");
  assert.ok(out.violations.some((v) => v.code === "POLICY_ID_MISMATCH"));
});

test("non-monotonic timestamp returns violation", () => {
  const events = validEvents();
  events[2] = { ...events[2], timestamp: 99 };

  const out = ReplayEngine.verify(events, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "violation");
  assert.ok(out.violations.some((v) => v.code === "NON_MONOTONIC_TIMESTAMP"));
});

test("strict mode returns ok when a valid state checkpoint exists", () => {
  const events = [
    ...validEvents(),
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: "a".repeat(64),
      timestamp: 102,
      policyId: "policy-A"
    }
  ];

  const out = ReplayEngine.verify(events);
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
});

test("malformed state checkpoint hash returns violation", () => {
  const events = [
    ...validEvents(),
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: "not-a-sha256",
      timestamp: 102,
      policyId: "policy-A"
    }
  ];

  const out = ReplayEngine.verify(events, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "violation");
  assert.ok(out.violations.some((v) => v.code === "INVALID_STATE_HASH"));
});
