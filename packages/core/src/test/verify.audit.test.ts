// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";

import { verifyAuditEvents } from "../verification/verifyAuditEvents.js";
import type { AuditEvent } from "../audit/AuditLog.js";

function baseEvents(policyId = "policy-A"): AuditEvent[] {
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
      policy_version: "v0.8",
      timestamp: 101,
      policyId
    },
    {
      type: "AUTH_EMITTED",
      authorization_id: "auth-1",
      intent_hash: "ih-1",
      expires_at: 200,
      timestamp: 102,
      policyId
    }
  ];
}

test("best-effort ok on valid event list", () => {
  const out = verifyAuditEvents(baseEvents(), { mode: "best-effort" });
  assert.equal(out.ok, true);
  assert.equal(out.status, "ok");
  assert.equal(out.violations.length, 0);
  assert.equal(out.policyId, "policy-A");
  assert.ok(typeof out.auditHeadHash === "string" && out.auditHeadHash.length === 64);
});

test("strict inconclusive without checkpoints", () => {
  const out = verifyAuditEvents(baseEvents());
  assert.equal(out.ok, false);
  assert.equal(out.status, "inconclusive");
  assert.ok(out.violations.some((v) => v.code === "NO_STATE_ANCHOR"));
});

test("mixed policyId invalid", () => {
  const events = baseEvents();
  events[2] = { ...events[2], policyId: "policy-B" };

  const out = verifyAuditEvents(events, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "MIXED_POLICY_ID"));
});

test("expectedPolicyId mismatch invalid", () => {
  const out = verifyAuditEvents(baseEvents("policy-A"), {
    mode: "best-effort",
    expectedPolicyId: "policy-Z"
  });

  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "POLICY_ID_MISMATCH"));
});

test("non-monotonic timestamp invalid", () => {
  const events = baseEvents();
  events[2] = { ...events[2], timestamp: 99 };

  const out = verifyAuditEvents(events, { mode: "best-effort" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "NON_MONOTONIC_TIMESTAMP"));
});

test("hash chain recompute is deterministic", () => {
  const events = [
    ...baseEvents(),
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: "a".repeat(64),
      timestamp: 103,
      policyId: "policy-A"
    }
  ];

  const a = verifyAuditEvents(events, { mode: "strict" });
  const b = verifyAuditEvents(events, { mode: "strict" });

  assert.equal(a.status, "ok");
  assert.equal(b.status, "ok");
  assert.equal(a.auditHeadHash, b.auditHeadHash);
  assert.ok(typeof a.auditHeadHash === "string" && a.auditHeadHash.length === 64);
});
