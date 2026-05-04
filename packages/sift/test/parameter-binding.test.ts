// SPDX-License-Identifier: Apache-2.0
/**
 * Parameter binding documentation tests.
 *
 * These tests demonstrate — NOT fix — the architectural property that Sift
 * receipts do not cryptographically bind parameter values.
 *
 * PURPOSE:
 *   Lock in and document the known security boundary so that future maintainers,
 *   cross-language adapter authors, and auditors have an executable specification
 *   of the limitation.
 *
 * PROPERTY UNDER TEST:
 *   A Sift receipt that approved tool T under policy P will be accepted by
 *   normalizeIntent and receiptToAuthorization regardless of the specific
 *   parameter values the adapter supplies.  The resulting AuthorizationV1.intent_hash
 *   commits to the ADAPTER-SUPPLIED params, not to the params Sift evaluated.
 *
 * THIS IS NOT A BUG.  The PEP still enforces intent binding at execution time:
 *   if the adapter issues AuthorizationV1 with params P2 but execution uses P1,
 *   the PEP will recompute intent_hash from P1 and find a mismatch → DENY.
 *   The gap is that the PEP cannot verify that Sift approved P2 specifically.
 *
 * See: docs/adapters/sift.md §"Parameter Binding Guarantee"
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { normalizeIntent }         from "../src/normalizeIntent.js";
import { receiptToAuthorization }  from "../src/receiptToAuthorization.js";
import { siftCanonicalJsonBytes }  from "../src/siftCanonical.js";
import type { SiftReceipt }        from "../src/verifyReceipt.js";
import type { NormalizedState }    from "../src/state.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Returns a pre-verified SiftReceipt for the "transfer" tool.
 *
 * The receipt represents Sift's decision to ALLOW the "transfer" tool under
 * "transfer-policy-v1".  The receipt does NOT include parameter values —
 * the params Sift evaluated (e.g. amount=1) are NOT present anywhere in the
 * receipt payload and NOT covered by the receipt's Ed25519 signature.
 */
function makeTransferReceipt(): SiftReceipt {
  return {
    receipt_version: "1.0",
    tenant_id:       "tenant-acme",
    agent_id:        "agent-001",
    action:          "call_tool",
    tool:            "transfer",
    decision:        "ALLOW",
    risk_tier:       2,
    timestamp:       "2026-04-14T12:00:00.000Z",
    nonce:           "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    policy_matched:  "transfer-policy-v1",
    // receipt_hash and signature are placeholders.
    // normalizeIntent and receiptToAuthorization operate on a pre-verified
    // SiftReceipt; they do not re-run verifyReceipt.
    receipt_hash:    "a".repeat(64),
    signature:       "placeholder",
  };
}

function makeBaseState(): NormalizedState {
  return { session_active: true, account_status: "active" } as NormalizedState;
}

function sha256hex(value: unknown): string {
  return createHash("sha256").update(siftCanonicalJsonBytes(value)).digest("hex");
}

// Fixed wall-clock for all time-sensitive assertions.
const FIXED_NOW = new Date(1_700_000_000_000);

// ─── PB-1: normalizeIntent accepts params that differ from what Sift evaluated ──

test("PB-1: normalizeIntent succeeds with adapter-supplied params regardless of what Sift evaluated", () => {
  const receipt = makeTransferReceipt();

  // The adapter supplies amount=100_000.
  // Sift was hypothetically asked about amount=1 — but that is NOT in the receipt
  // and NOT verifiable from the receipt alone.
  const adapterParams = { amount: 100_000, destination: "attacker_account" };

  const result = normalizeIntent({ receipt, params: adapterParams });

  // normalizeIntent MUST succeed — params are not bound by the receipt.
  assert.ok(
    result.ok,
    `normalizeIntent MUST succeed for structurally valid params: ${
      !result.ok ? result.code + ": " + result.message : ""
    }`
  );
  if (!result.ok) return;

  // The intent reflects the adapter-supplied values, not anything Sift signed.
  assert.equal(result.intent.type, "EXECUTE");
  assert.equal(result.intent.tool, "transfer");
  // normalizeIntent returns Object.create(null) params; use JSON round-trip to
  // compare values without requiring identical prototype chains.
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(result.intent.params)),
    adapterParams,
    "intent.params MUST equal the adapter-supplied params"
  );
});

// ─── PB-2: intent_hash commits to adapter-supplied params, NOT Sift-evaluated ──

test("PB-2: intent_hash in AuthorizationV1 equals SHA-256 of adapter-supplied params — not Sift-evaluated params", () => {
  const receipt      = makeTransferReceipt();
  const adapterParams = { amount: 100_000, destination: "attacker_account" };

  const intentResult = normalizeIntent({ receipt, params: adapterParams });
  assert.ok(intentResult.ok);

  const authResult = receiptToAuthorization({
    receipt,
    intent:     intentResult.intent,
    state:      makeBaseState(),
    issuer:     "adapter-issuer",
    audience:   "pep-payments",
    keyId:      "adapter-key-1",
    ttlSeconds: 30,
    now:        FIXED_NOW,
  });
  assert.ok(
    authResult.ok,
    `receiptToAuthorization MUST succeed: ${!authResult.ok ? authResult.code : ""}`
  );
  if (!authResult.ok) return;

  // The expected hash is over the adapter-supplied intent — not Sift's evaluation.
  const expectedHash = sha256hex(intentResult.intent);

  assert.equal(
    authResult.authorization.intent_hash,
    expectedHash,
    "intent_hash MUST equal SHA-256(sift_canonical(adapter-supplied intent))"
  );

  // Sanity-check the negative: the hash is NOT over what Sift (hypothetically) evaluated.
  const siftEvaluatedIntent = {
    type:   "EXECUTE",
    tool:   "transfer",
    params: { amount: 1, destination: "safe_account" }, // what Sift was asked
  };
  assert.notEqual(
    authResult.authorization.intent_hash,
    sha256hex(siftEvaluatedIntent),
    "intent_hash MUST NOT equal the hash of the params Sift (hypothetically) evaluated"
  );
});

// ─── PB-3: same receipt, different params → same auth_id, different intent_hash ─

test("PB-3: using the same receipt with different params produces the same auth_id but different intent_hash values", () => {
  const receipt = makeTransferReceipt();

  const paramsSmall  = { amount: 1,       destination: "safe_account"     };
  const paramsLarge  = { amount: 100_000, destination: "attacker_account" };

  const intentSmall  = normalizeIntent({ receipt, params: paramsSmall });
  const intentLarge  = normalizeIntent({ receipt, params: paramsLarge });
  assert.ok(intentSmall.ok);
  assert.ok(intentLarge.ok);
  if (!intentSmall.ok || !intentLarge.ok) return;

  const base = {
    receipt,
    state:      makeBaseState(),
    issuer:     "adapter-issuer",
    audience:   "pep-payments",
    keyId:      "adapter-key-1",
    ttlSeconds: 30,
    now:        FIXED_NOW,
  };

  const authSmall = receiptToAuthorization({ ...base, intent: intentSmall.intent });
  const authLarge = receiptToAuthorization({ ...base, intent: intentLarge.intent });
  assert.ok(authSmall.ok);
  assert.ok(authLarge.ok);
  if (!authSmall.ok || !authLarge.ok) return;

  // auth_id is receipt.nonce — always the same for the same receipt.
  assert.equal(
    authSmall.authorization.auth_id,
    authLarge.authorization.auth_id,
    "auth_id MUST equal receipt.nonce regardless of params"
  );
  assert.equal(
    authSmall.authorization.auth_id,
    receipt.nonce,
    "auth_id MUST be exactly receipt.nonce"
  );

  // intent_hash MUST differ because params differ.
  assert.notEqual(
    authSmall.authorization.intent_hash,
    authLarge.authorization.intent_hash,
    "intent_hash MUST differ when adapter-supplied params differ"
  );

  // Each intent_hash must equal the locally-computed hash for its own params.
  assert.equal(authSmall.authorization.intent_hash, sha256hex(intentSmall.intent));
  assert.equal(authLarge.authorization.intent_hash, sha256hex(intentLarge.intent));
});

// ─── PB-4: receipt contains no params field — the absence is structural ─────────

test("PB-4: the SiftReceipt type has no params field — absence is structural, not a parsing artefact", () => {
  const receipt = makeTransferReceipt();

  // Verify that the receipt object genuinely does not carry params.
  assert.ok(
    !Object.prototype.hasOwnProperty.call(receipt, "params"),
    "SiftReceipt MUST NOT have a 'params' field — Sift does not include params in the receipt"
  );
  assert.ok(
    !Object.prototype.hasOwnProperty.call(receipt, "params_hash"),
    "SiftReceipt MUST NOT have a 'params_hash' field — Sift does not sign params"
  );

  // The tool field IS present and IS covered by the receipt signature.
  assert.ok(
    Object.prototype.hasOwnProperty.call(receipt, "tool"),
    "SiftReceipt MUST have a 'tool' field — tool identity is signed"
  );
});
