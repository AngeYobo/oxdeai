// SPDX-License-Identifier: Apache-2.0
/**
 * audit.genesis.test.ts
 *
 * Regression tests for the audit hash chain genesis seed.
 *
 * Protocol spec: packages/conformance/vectors/audit-chain.json audit-chain-001
 *   SHA256("OxDeAI::GENESIS::v1") = "db393af6a9cf189c2b250a0a7dea0c776a3d446c9f51999426f933c53416238b"
 *
 * These tests ensure:
 *   1. AUDIT_GENESIS_HASH matches the conformance vector exactly.
 *   2. HashChainedLog and verifyAuditEvents start from the same genesis and
 *      therefore produce the same head hash for the same event sequence.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { AUDIT_GENESIS_HASH } from "../audit/auditGenesis.js";
import { HashChainedLog } from "../audit/HashChainedLog.js";
import { verifyAuditEvents } from "../verification/verifyAuditEvents.js";
import type { AuditEvent } from "../audit/AuditLog.js";

// Conformance vector audit-chain-001 expected value.
const CONFORMANCE_GENESIS = "db393af6a9cf189c2b250a0a7dea0c776a3d446c9f51999426f933c53416238b";

test("AUDIT_GENESIS_HASH matches conformance vector audit-chain-001", () => {
  assert.equal(
    AUDIT_GENESIS_HASH,
    CONFORMANCE_GENESIS,
    "genesis seed must equal SHA256('OxDeAI::GENESIS::v1') per conformance spec"
  );
});

test("HashChainedLog and verifyAuditEvents produce the same head hash for a single event", () => {
  const event: AuditEvent = {
    type: "INTENT_RECEIVED",
    intent_hash: "d17664c344609e5bd498107bcf12d31bfa289afaa3516b34d96f1d6785a8e0b9",
    agent_id: "agent-1",
    timestamp: 1730000000,
    policyId: "a".repeat(64)
  };

  // Head hash from HashChainedLog.
  const log = new HashChainedLog();
  log.append(event);
  const logHead = log.headHash();

  // Head hash from verifyAuditEvents.
  const result = verifyAuditEvents([event], { mode: "best-effort" });
  assert.equal(result.status, "ok");
  const verifyHead = result.auditHeadHash;

  assert.equal(logHead, verifyHead,
    "HashChainedLog.headHash() and verifyAuditEvents auditHeadHash must agree for the same event sequence"
  );

  // Both must also match the expected value from conformance vector audit-chain-002.
  // head_1 when starting from audit-chain-001 genesis and applying that same event.
  const CONFORMANCE_HEAD_1 = "c673c25dd89343acc3475712bdf30e41f1ef0e3a41f7bc8454885646e720ab08";
  assert.equal(logHead, CONFORMANCE_HEAD_1,
    "head after first event must match conformance vector audit-chain-002 head_1"
  );
});
