// SPDX-License-Identifier: Apache-2.0

/**
 * Property-based tests for verifyReceipt.
 *
 * Each property verifies a security invariant at the execution boundary:
 *   P1  Valid receipts verify        — correct structure, hash, signature, fresh ts
 *   P2  Determinism                  — same inputs always return the same result
 *   P3  Post-signature mutation      — any signed field change after signing fails
 *   P4  Receipt hash mismatch        — wrong or malformed hash always fails
 *   P5  DENY decision enforcement    — DENY fails by default; bypassed with flag
 *   P6  Freshness window             — stale / too-future receipts rejected
 *   P7  Structural invalidity        — bad field types, missing fields, non-objects fail
 *   P8  Wrong public key             — verification with wrong key always fails
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fc from "fast-check";
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import {
  verifyReceipt,
  type VerifyReceiptOptions,
} from "../src/verifyReceipt.js";

// ─── Run budget ───────────────────────────────────────────────────────────────

const RUNS = 50;

// ─── Canonical JSON ───────────────────────────────────────────────────────────
//
// Mirrors source exactly: lexicographically sorted keys, no whitespace, UTF-8.

type JsonPrimitive = string | number | boolean | null;
type JsonObject = { [key: string]: JsonValue };
type JsonArray = JsonValue[];
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

function canonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite: ${value}`);
    return value;
  }
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const out: JsonObject = {};
    for (const k of Object.keys(value as object).sort()) {
      out[k] = canonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf-8");
}

// ─── Receipt hash ─────────────────────────────────────────────────────────────
//
// SHA-256 over canonical JSON of the receipt EXCLUDING `signature` and
// `receipt_hash` — the two fields outside the hash scope.
// Mirrors source computeReceiptHash exactly.

function computeTestHash(receipt: Record<string, unknown>): string {
  const { signature: _s, receipt_hash: _h, ...payload } = receipt;
  return createHash("sha256").update(canonicalBytes(payload)).digest("hex");
}

// ─── Ed25519 helpers ──────────────────────────────────────────────────────────

interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

function makeKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

// Mirrors source signature scope: canonical JSON of the receipt EXCLUDING
// `signature` (receipt_hash IS included — it is part of the signed object).
// Caller passes a payload that already contains receipt_hash but not signature.
function signPayload(payload: Record<string, unknown>, privateKeyPem: string): string {
  return cryptoSign(null, canonicalBytes(payload), privateKeyPem).toString("base64");
}

// ─── Valid receipt builder ────────────────────────────────────────────────────

interface SignedReceiptFixture {
  receipt: Record<string, unknown>;
  publicKeyPem: string;
  privateKeyPem: string;
}

/**
 * Fixed baseline `now` for all freshness-sensitive tests.
 * Receipts built with the default timestamp are fresh relative to FIXED_NOW.
 */
const FIXED_NOW = new Date("2026-04-14T12:00:00.000Z");
const BASELINE_TIMESTAMP = FIXED_NOW.toISOString();

/**
 * Builds a structurally valid, correctly signed receipt.
 *
 * Build order (matching the verification pipeline):
 *   1. Apply overrides to base fields — overrides are part of the hash preimage.
 *   2. Compute receipt_hash = SHA-256(canonical(base)).
 *      Neither `signature` nor `receipt_hash` is in `base` at this point;
 *      their absence from the preimage is guaranteed by construction.
 *   3. Format receipt_hash as bare hex or "sha256:<hex>".
 *   4. Sign canonical(base + receipt_hash).
 *      No `signature` field is present yet.
 *   5. Attach signature to produce the complete receipt.
 */
function makeSignedReceipt(
  overrides: Record<string, unknown> = {},
  hashFormat: "hex" | "sha256:hex" = "hex",
  keypair?: KeyPair
): SignedReceiptFixture {
  const kp = keypair ?? makeKeyPair();

  // Base payload fields.  `signature` and `receipt_hash` are intentionally
  // absent here — both are computed below.
  const base: Record<string, unknown> = {
    receipt_version: "1.0",
    tenant_id: "tenant-test",
    agent_id: "agent-test",
    action: "transfer_funds",
    tool: "payments_api",
    decision: "ALLOW",
    risk_tier: 1,
    timestamp: BASELINE_TIMESTAMP,
    nonce: "11111111-1111-1111-1111-111111111111",
    policy_matched: "payments-policy-v1",
    ...overrides,
  };

  // Hash preimage = base (computeTestHash strips sig+hash; no-op on base).
  const hashHex = computeTestHash(base);
  const receiptHash = hashFormat === "sha256:hex" ? `sha256:${hashHex}` : hashHex;

  // Signature preimage = base + receipt_hash (no signature field yet).
  const withHash: Record<string, unknown> = { ...base, receipt_hash: receiptHash };
  const signature = signPayload(withHash, kp.privateKeyPem);

  return {
    receipt: { ...withHash, signature },
    publicKeyPem: kp.publicKeyPem,
    privateKeyPem: kp.privateKeyPem,
  };
}

// ─── Mutation helper ──────────────────────────────────────────────────────────

/** Shallow-clones receipt with one field replaced — does NOT re-sign. */
function cloneWithField(
  receipt: Record<string, unknown>,
  field: string,
  value: unknown
): Record<string, unknown> {
  return { ...receipt, [field]: value };
}

// ─── Arbitraries ──────────────────────────────────────────────────────────────

const arbNonEmptyString = fc.string({ minLength: 1, maxLength: 32 });

// ═══════════════════════════════════════════════════════════════════════════════
// P1. Valid signed receipts verify successfully
// ═══════════════════════════════════════════════════════════════════════════════

test("P1: valid signed receipts with diverse payloads always verify successfully", () => {
  fc.assert(
    fc.property(
      fc.record({
        tenant_id: arbNonEmptyString,
        agent_id: arbNonEmptyString,
        action: arbNonEmptyString,
        tool: arbNonEmptyString,
        risk_tier: fc.integer({ min: 0, max: 10 }),
        nonce: fc.uuid(),
        policy_matched: arbNonEmptyString,
        hashFormat: fc.constantFrom("hex" as const, "sha256:hex" as const),
      }),
      ({ tenant_id, agent_id, action, tool, risk_tier, nonce, policy_matched, hashFormat }) => {
        const { receipt, publicKeyPem } = makeSignedReceipt(
          { tenant_id, agent_id, action, tool, risk_tier, nonce, policy_matched },
          hashFormat
        );

        const result = verifyReceipt(receipt, {
          publicKeyPem,
          now: FIXED_NOW,
          maxAgeMs: 30_000,
        });

        assert.equal(
          result.ok,
          true,
          `valid signed receipt must verify; got code: ${
            result.ok ? "(ok)" : (result as { code: string }).code
          }`
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P2. Determinism
// ═══════════════════════════════════════════════════════════════════════════════

test("P2: verifyReceipt is deterministic — identical inputs always produce identical results", () => {
  fc.assert(
    fc.property(
      fc.record({
        tenant_id: arbNonEmptyString,
        agent_id: arbNonEmptyString,
      }),
      ({ tenant_id, agent_id }) => {
        const { receipt, publicKeyPem } = makeSignedReceipt({ tenant_id, agent_id });
        const options: VerifyReceiptOptions = { publicKeyPem, now: FIXED_NOW };

        const r1 = verifyReceipt(receipt, options);
        const r2 = verifyReceipt(receipt, options);

        assert.deepStrictEqual(
          r1,
          r2,
          "two calls with identical inputs must return deeply equal results"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P3. Post-signature mutation always fails
// ═══════════════════════════════════════════════════════════════════════════════
//
// All fields covered by the receipt hash preimage or the signature scope are
// listed below.  Mutating any of them after signing must cause verification to
// fail regardless of which step detects the change.
//
// Expected detection paths per field (verification order: structural → version
// → ALLOW/DENY → freshness → hash → signature):
//
//   decision     → DENY_DECISION (step 3) — tampered to "DENY", structurally valid
//   timestamp    → INVALID_RECEIPT_HASH (step 5) — different valid ISO in hash preimage
//   receipt_hash → INVALID_RECEIPT_HASH (step 5) — claimed hash no longer matches
//   all others   → INVALID_RECEIPT_HASH (step 5) — fields are in the hash preimage

const SIGNED_FIELDS = [
  "action",
  "tool",
  "tenant_id",
  "agent_id",
  "policy_matched",
  "nonce",
  "decision",
  "risk_tier",
  "timestamp",
  "receipt_hash",
] as const;

type SignedField = (typeof SIGNED_FIELDS)[number];

// A timestamp 1 ms earlier than the baseline — structurally valid, still fresh,
// but different from BASELINE_TIMESTAMP so the hash preimage changes.
const TAMPERED_TIMESTAMP = new Date(FIXED_NOW.getTime() - 1).toISOString();

test("P3: mutating any covered field after signing always causes verification to fail without throwing", () => {
  // Fixed receipt; the property varies over which field is tampered.
  const { receipt, publicKeyPem } = makeSignedReceipt();

  fc.assert(
    fc.property(
      fc.constantFrom<SignedField>(...SIGNED_FIELDS),
      (field) => {
        const original = receipt[field];

        // Use structurally valid replacement values where possible so that
        // detection reaches the hash / signature checks rather than being
        // short-circuited by a structural guard.
        let tampered: unknown;
        if (field === "decision") {
          // "DENY" is a valid decision value; fails at DENY_DECISION (step 3).
          tampered = "DENY";
        } else if (field === "timestamp") {
          // Different valid ISO string still within freshness; fails at
          // INVALID_RECEIPT_HASH (step 5) because timestamp is in hash preimage.
          tampered = TAMPERED_TIMESTAMP;
        } else if (field === "receipt_hash") {
          // A well-formed 64-char hex hash that differs from the correct one;
          // fails at INVALID_RECEIPT_HASH (step 5).
          tampered = "0".repeat(64);
        } else if (typeof original === "number") {
          // Different non-negative integer; fails at INVALID_RECEIPT_HASH (step 5).
          tampered = (original as number) + 1;
        } else {
          // Different non-empty string; fails at INVALID_RECEIPT_HASH (step 5).
          tampered = String(original) + "_tampered";
        }

        const mutated = cloneWithField(receipt, field, tampered);

        let result;
        try {
          result = verifyReceipt(mutated, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(
            `verifyReceipt threw instead of returning { ok: false } for tampered field '${field}': ${String(e)}`
          );
          return;
        }

        assert.equal(
          result.ok,
          false,
          `tampering field '${field}' must cause verification to fail`
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P4. Receipt hash mismatch or malformed hash
// ═══════════════════════════════════════════════════════════════════════════════

test("P4a: wrong receipt_hash (correct format, wrong content) always fails with INVALID_RECEIPT_HASH", () => {
  // Fixed receipt so the correct hash is stable across all runs.
  const { receipt, publicKeyPem } = makeSignedReceipt();
  const correctHash = computeTestHash(receipt);

  fc.assert(
    fc.property(
      // 64-char lowercase hex strings, excluding the correct hash.
      // For every such string: it is a non-empty value (passes structural check),
      // steps 1–4 all pass with the unchanged receipt, and step 5 fires because
      // claimedHash ≠ recomputedHash.
      fc
        .string({
          unit: fc.constantFrom("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"),
          minLength: 64,
          maxLength: 64,
        })
        .filter((h: string) => h !== correctHash),
      (wrongHex) => {
        const mutated = cloneWithField(receipt, "receipt_hash", wrongHex);

        let result;
        try {
          result = verifyReceipt(mutated, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(`verifyReceipt threw on wrong receipt_hash: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, "wrong receipt_hash must fail verification");
        if (!result.ok) {
          // The generated hash is structurally valid so steps 1–4 pass; step 5
          // (hash integrity check) is the first to fire and must produce this code.
          assert.equal(result.code, "INVALID_RECEIPT_HASH");
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("P4b: malformed receipt_hash (any short non-hash string) always fails without throwing", () => {
  // Any string of length 1–32 is too short to be a 64-char hex hash or a
  // "sha256:<64 hex chars>" (71 chars), so it will always mismatch at step 5
  // (or fail the non-empty check if it were empty, but minLength: 1 prevents that).
  const { receipt, publicKeyPem } = makeSignedReceipt();

  fc.assert(
    fc.property(
      fc.string({ minLength: 1, maxLength: 32 }),
      (badHash) => {
        const mutated = cloneWithField(receipt, "receipt_hash", badHash);

        let result;
        try {
          result = verifyReceipt(mutated, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(`verifyReceipt threw on malformed receipt_hash: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, "malformed receipt_hash must fail verification");
      }
    ),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P5. DENY decision enforcement
// ═══════════════════════════════════════════════════════════════════════════════

test("P5a: DENY decision always fails with default options (requireAllowDecision defaults to true)", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString,
      (tenant_id) => {
        const { receipt, publicKeyPem } = makeSignedReceipt({ tenant_id, decision: "DENY" });

        let result;
        try {
          result = verifyReceipt(receipt, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(`verifyReceipt threw on DENY receipt: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, "DENY receipt must fail by default");
        if (!result.ok) {
          assert.equal(
            result.code,
            "DENY_DECISION",
            "error code must be DENY_DECISION for a denied receipt"
          );
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("P5b: DENY decision with requireAllowDecision: false passes when receipt is otherwise valid", () => {
  const { receipt, publicKeyPem } = makeSignedReceipt({ decision: "DENY" });

  const result = verifyReceipt(receipt, {
    publicKeyPem,
    now: FIXED_NOW,
    requireAllowDecision: false,
  });

  assert.equal(
    result.ok,
    true,
    "valid DENY receipt must pass when requireAllowDecision is false"
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P6. Freshness window
//
// ageMs = nowMs − receiptMs
//   fresh:              ageMs ∈ [0, MAX_AGE_MS]     boundary MAX_AGE_MS is included
//                                                     (source uses strict >)
//   stale:              ageMs > MAX_AGE_MS            strict; min = MAX_AGE_MS + 1
//   future within skew: ageMs ∈ [−MAX_SKEW_MS, 0)   boundary −MAX_SKEW_MS included
//                                                     (source uses strict <)
//   future too far:     ageMs < −MAX_SKEW_MS          strict; min skewMs = MAX_SKEW_MS + 1
// ═══════════════════════════════════════════════════════════════════════════════

const NOW_MS    = FIXED_NOW.getTime();
const MAX_AGE_MS  = 30_000;  // DEFAULT_MAX_AGE_MS in source
const MAX_SKEW_MS =  5_000;  // MAX_FUTURE_SKEW_MS in source

test("P6a: receipts within the freshness window always verify successfully", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: MAX_AGE_MS }),
      (ageMs) => {
        const timestamp = new Date(NOW_MS - ageMs).toISOString();
        const { receipt, publicKeyPem } = makeSignedReceipt({ timestamp });

        const result = verifyReceipt(receipt, {
          publicKeyPem,
          now: FIXED_NOW,
          maxAgeMs: MAX_AGE_MS,
        });

        assert.equal(
          result.ok,
          true,
          `receipt with age ${ageMs}ms must be within the freshness window`
        );
      }
    ),
    { numRuns: RUNS }
  );
});

test("P6b: stale receipts (age > maxAgeMs) are rejected with STALE_RECEIPT", () => {
  fc.assert(
    fc.property(
      // min = MAX_AGE_MS + 1: strictly over the boundary (source: ageMs > maxAgeMs).
      fc.integer({ min: MAX_AGE_MS + 1, max: MAX_AGE_MS + 3_600_000 }),
      (ageMs) => {
        const timestamp = new Date(NOW_MS - ageMs).toISOString();
        const { receipt, publicKeyPem } = makeSignedReceipt({ timestamp });

        let result;
        try {
          result = verifyReceipt(receipt, {
            publicKeyPem,
            now: FIXED_NOW,
            maxAgeMs: MAX_AGE_MS,
          });
        } catch (e) {
          assert.fail(`verifyReceipt threw on stale receipt: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, `receipt with age ${ageMs}ms must be stale`);
        if (!result.ok) {
          assert.equal(result.code, "STALE_RECEIPT");
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("P6c: receipts slightly in the future (within skew tolerance) verify successfully", () => {
  fc.assert(
    fc.property(
      // max = MAX_SKEW_MS: boundary is included (source: ageMs < -MAX_FUTURE_SKEW_MS,
      // so ageMs = -MAX_SKEW_MS does NOT fail).
      fc.integer({ min: 1, max: MAX_SKEW_MS }),
      (skewMs) => {
        const timestamp = new Date(NOW_MS + skewMs).toISOString();
        const { receipt, publicKeyPem } = makeSignedReceipt({ timestamp });

        const result = verifyReceipt(receipt, {
          publicKeyPem,
          now: FIXED_NOW,
          maxAgeMs: MAX_AGE_MS,
        });

        assert.equal(
          result.ok,
          true,
          `receipt ${skewMs}ms in the future (≤ ${MAX_SKEW_MS}ms skew) must pass`
        );
      }
    ),
    { numRuns: RUNS }
  );
});

test("P6d: receipts too far in the future (beyond skew tolerance) are rejected with INVALID_TIMESTAMP", () => {
  fc.assert(
    fc.property(
      // min = MAX_SKEW_MS + 1: strictly beyond the boundary.
      fc.integer({ min: MAX_SKEW_MS + 1, max: MAX_SKEW_MS + 3_600_000 }),
      (skewMs) => {
        const timestamp = new Date(NOW_MS + skewMs).toISOString();
        const { receipt, publicKeyPem } = makeSignedReceipt({ timestamp });

        let result;
        try {
          result = verifyReceipt(receipt, {
            publicKeyPem,
            now: FIXED_NOW,
            maxAgeMs: MAX_AGE_MS,
          });
        } catch (e) {
          assert.fail(`verifyReceipt threw on future receipt: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, `receipt ${skewMs}ms too far in future must fail`);
        if (!result.ok) {
          assert.equal(result.code, "INVALID_TIMESTAMP");
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P7. Structural invalidity fails closed
// ═══════════════════════════════════════════════════════════════════════════════

test("P7a: invalid values in required string fields always fail without throwing", () => {
  const REQUIRED_STRING_FIELDS = [
    "receipt_version",
    "tenant_id",
    "agent_id",
    "action",
    "tool",
    "timestamp",
    "nonce",
    "policy_matched",
    "receipt_hash",
    "signature",
  ] as const;

  // Values rejected by isNonEmptyString — every required string field rejects these.
  const arbInvalidStringValue: fc.Arbitrary<unknown> = fc.oneof(
    fc.constant(""),
    fc.constant(null),
    fc.constant(undefined),
    fc.constant(0),
    fc.constant(false),
    fc.constant([]),
    fc.constant({}),
  );

  const { receipt, publicKeyPem } = makeSignedReceipt();

  fc.assert(
    fc.property(
      fc.constantFrom(...REQUIRED_STRING_FIELDS),
      arbInvalidStringValue,
      (field, badValue) => {
        const mutated = cloneWithField(receipt, field, badValue);

        let result;
        try {
          result = verifyReceipt(mutated, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(`verifyReceipt threw on bad value for '${field}': ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, `invalid value for '${field}' must fail`);
      }
    ),
    { numRuns: RUNS }
  );
});

test("P7b: invalid risk_tier values (float, negative, non-number) always fail without throwing", () => {
  const arbInvalidRiskTier: fc.Arbitrary<unknown> = fc.oneof(
    fc.float({ noNaN: true, noDefaultInfinity: true }).filter((n: number) => !Number.isInteger(n)),
    fc.integer({ min: -1_000_000, max: -1 }),
    fc.constant(null),
    fc.constant("1"),
    fc.constant(true),
    fc.constant([]),
    fc.constant({}),
  );

  const { receipt, publicKeyPem } = makeSignedReceipt();

  fc.assert(
    fc.property(arbInvalidRiskTier, (badTier) => {
      const mutated = cloneWithField(receipt, "risk_tier", badTier);

      let result;
      try {
        result = verifyReceipt(mutated, { publicKeyPem, now: FIXED_NOW });
      } catch (e) {
        assert.fail(`verifyReceipt threw on invalid risk_tier: ${String(e)}`);
        return;
      }

      assert.equal(result.ok, false, "invalid risk_tier must fail structural validation");
    }),
    { numRuns: RUNS }
  );
});

test("P7c: missing required fields always fail without throwing", () => {
  const REQUIRED_FIELDS = [
    "receipt_version",
    "tenant_id",
    "agent_id",
    "action",
    "tool",
    "decision",
    "risk_tier",
    "timestamp",
    "nonce",
    "policy_matched",
    "receipt_hash",
    "signature",
  ] as const;

  const { receipt, publicKeyPem } = makeSignedReceipt();

  fc.assert(
    fc.property(
      fc.constantFrom(...REQUIRED_FIELDS),
      (field) => {
        const withoutField: Record<string, unknown> = {};
        for (const k of Object.keys(receipt)) {
          if (k !== field) withoutField[k] = receipt[k];
        }

        let result;
        try {
          result = verifyReceipt(withoutField, { publicKeyPem, now: FIXED_NOW });
        } catch (e) {
          assert.fail(`verifyReceipt threw on missing field '${field}': ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, `missing field '${field}' must fail`);
      }
    ),
    { numRuns: RUNS }
  );
});

test("P7d: non-object top-level input (null, array, primitive) always fails without throwing", () => {
  // parseReceipt rejects anything that is not a non-null plain object.
  // This exercises the top-level structural guard before any field validation.
  const { publicKeyPem } = makeSignedReceipt();

  const arbNonObject: fc.Arbitrary<unknown> = fc.oneof(
    fc.constant(null),
    fc.constant(undefined),
    fc.array(arbNonEmptyString, { maxLength: 5 }),
    fc.string({ minLength: 0, maxLength: 32 }),
    fc.integer({ min: -100_000, max: 100_000 }),
    fc.boolean(),
  );

  fc.assert(
    fc.property(arbNonObject, (badReceipt) => {
      let result;
      try {
        result = verifyReceipt(badReceipt, { publicKeyPem, now: FIXED_NOW });
      } catch (e) {
        assert.fail(`verifyReceipt threw on non-object input: ${String(e)}`);
        return;
      }

      assert.equal(result.ok, false, "non-object receipt must fail with MALFORMED_RECEIPT");
      if (!result.ok) {
        assert.equal(result.code, "MALFORMED_RECEIPT");
      }
    }),
    { numRuns: RUNS }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// P8. Wrong public key always fails
// ═══════════════════════════════════════════════════════════════════════════════

// Pre-generate a wrong keypair once.  This avoids 50 extra generateKeyPairSync
// calls inside the property while still demonstrating the invariant across
// receipts with different payloads (via varied tenant_id).
const WRONG_KEYPAIR = makeKeyPair();

test("P8: verifying a receipt with the wrong Ed25519 public key always fails without throwing", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString,
      (tenant_id) => {
        // Sign with keypair A; attempt verification with the unrelated keypair B.
        const { receipt } = makeSignedReceipt({ tenant_id });

        let result;
        try {
          result = verifyReceipt(receipt, {
            publicKeyPem: WRONG_KEYPAIR.publicKeyPem,
            now: FIXED_NOW,
          });
        } catch (e) {
          assert.fail(`verifyReceipt threw on wrong public key: ${String(e)}`);
          return;
        }

        assert.equal(result.ok, false, "wrong public key must cause verification to fail");
      }
    ),
    { numRuns: RUNS }
  );
});
