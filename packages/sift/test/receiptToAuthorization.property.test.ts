// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based tests for receiptToAuthorization.
 *
 * P1  – determinism: identical inputs produce structurally equal outputs
 * P2  – binding correctness: auth_id, policy_id, issuer, audience, decision, version
 * P3  – hash correctness: intent_hash and state_hash match local SHA-256 of canonical JSON
 * P4  – time derivation: issued_at = floor(nowMs/1000), expires_at = issued_at + ttl, default TTL = 30
 * P5  – invalid TTL fails closed: 0, negative, float, NaN, Infinity
 * P6  – empty binding strings fail with specific codes (INVALID_ISSUER / _AUDIENCE / _KEY_ID)
 * P7  – DENY receipt → INVALID_RECEIPT_DECISION
 * P8  – empty policy_matched → INVALID_POLICY_ID
 * P9  – invalid Date → INVALID_TIMESTAMP
 * P10 – signing payload shape: sig === "" in authorization, no `sig` own property in signingPayload
 * P11 – null intent or null state → INVALID_BINDING_INPUT
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fc from "fast-check";
import { receiptToAuthorization } from "../src/receiptToAuthorization.js";
import type { OxDeAIIntent } from "../src/normalizeIntent.js";
import type { NormalizedState } from "../src/state.js";
import { arbDeterministicObject } from "./helpers/propertyArbitraries.js";

// ─── Local canonical JSON helpers ─────────────────────────────────────────────
// Must exactly mirror the implementation in receiptToAuthorization.ts so that
// test-side hash computations produce the same bytes without importing internals.

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [k: string]: JsonValue };

function localCanonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Non-finite number: ${value}`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return (value as unknown[]).map(localCanonicalize);
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value) as unknown;
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(
        `Non-plain object: ${Object.prototype.toString.call(value)}`
      );
    }
    const keys = Object.keys(value as object).sort();
    const out = Object.create(null) as { [k: string]: JsonValue };
    for (const k of keys) {
      out[k] = localCanonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

const textEncoder = new TextEncoder();

function localCanonicalHash(value: unknown): string {
  const json = JSON.stringify(localCanonicalize(value));
  return createHash("sha256").update(textEncoder.encode(json)).digest("hex");
}

// ─── Fixture builders ─────────────────────────────────────────────────────────

function makeReceipt(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    receipt_version: "SiftReceiptV1",
    tenant_id: "tenant-abc",
    agent_id: "agent-xyz",
    action: "call_tool",
    tool: "weather_lookup",
    decision: "ALLOW",
    risk_tier: 1,
    timestamp: new Date(Date.now() - 1000).toISOString(),
    nonce: "nonce-" + Math.random().toString(36).slice(2),
    policy_matched: "policy-default",
    receipt_hash: "a".repeat(64),
    signature: "sig-placeholder",
    ...overrides,
  };
}

function makeIntent(
  tool = "weather_lookup",
  params: Record<string, unknown> = { city: "Paris" }
): OxDeAIIntent {
  return { type: "EXECUTE", tool, params } as OxDeAIIntent;
}

function makeState(overrides: Record<string, unknown> = {}): NormalizedState {
  return { user_role: "operator", session_active: true, ...overrides } as NormalizedState;
}

/** Non-empty string arbitrary. */
function arbNonEmptyString(): fc.Arbitrary<string> {
  return fc.string({ minLength: 1, maxLength: 40 });
}

/** Arbitrary for positive safe integers (valid TTL range). */
function arbPositiveSafeInt(): fc.Arbitrary<number> {
  return fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER });
}

/** Arbitrary for a valid `now` Date (finite millisecond timestamp). */
function arbValidDate(): fc.Arbitrary<Date> {
  return fc.integer({ min: 0, max: 2_000_000_000_000 }).map((ms) => new Date(ms));
}

// ─── P1: Determinism ──────────────────────────────────────────────────────────

test("P1 – receiptToAuthorization is deterministic: same inputs produce equal outputs", () => {
  fc.assert(
    fc.property(
      arbDeterministicObject(1),
      arbDeterministicObject(1),
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbPositiveSafeInt(),
      arbValidDate(),
      (intentParams, stateData, issuer, audience, keyId, ttlSeconds, now) => {
        const receipt = makeReceipt();
        const intent = makeIntent("tool_a", intentParams);
        const state = stateData as NormalizedState;

        const input = { receipt: receipt as never, intent, state, issuer, audience, keyId, ttlSeconds, now };
        const r1 = receiptToAuthorization(input);
        const r2 = receiptToAuthorization(input);

        assert.deepStrictEqual(r1, r2);
      }
    )
  );
});

// ─── P2: Binding correctness ──────────────────────────────────────────────────
// Varies nonce and policy_matched independently via separate arbitraries, then
// checks the output contains the exact input values — not just some non-empty
// string. This rules out any value-substitution bug in the binding step.

test("P2 – receiptToAuthorization binds nonce→auth_id, policy_matched→policy_id, and propagates issuer/audience/version/decision", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),  // nonce
      arbNonEmptyString(),  // policy_matched
      arbNonEmptyString(),  // issuer
      arbNonEmptyString(),  // audience
      arbNonEmptyString(),  // keyId
      (nonce, policyMatched, issuer, audience, keyId) => {
        const receipt = makeReceipt({ nonce, policy_matched: policyMatched });
        const intent = makeIntent();
        const state = makeState();
        const now = new Date(1_700_000_000_000);

        const result = receiptToAuthorization({
          receipt: receipt as never,
          intent,
          state,
          issuer,
          audience,
          keyId,
          ttlSeconds: 60,
          now,
        });

        assert.ok(result.ok, `Expected ok: true, got code=${!result.ok && result.code}`);

        const { authorization } = result;
        // Direct binding: each output field must equal its specific input source.
        assert.equal(authorization.auth_id, nonce);
        assert.equal(authorization.policy_id, policyMatched);
        assert.equal(authorization.issuer, issuer);
        assert.equal(authorization.audience, audience);
        assert.equal(authorization.decision, "ALLOW");
        assert.equal(authorization.version, "AuthorizationV1");
      }
    )
  );
});

// ─── P3: Hash correctness ─────────────────────────────────────────────────────

test("P3a – intent_hash equals local SHA-256 of canonical JSON of intent", () => {
  fc.assert(
    fc.property(
      arbDeterministicObject(2),
      (params) => {
        const intent = makeIntent("test_tool", params);
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent,
          state: makeState(),
          issuer: "iss",
          audience: "aud",
          keyId: "kid-1",
          ttlSeconds: 30,
          now: new Date(1_700_000_000_000),
        });

        assert.ok(result.ok);
        assert.equal(result.authorization.intent_hash, localCanonicalHash(intent));
      }
    )
  );
});

test("P3b – state_hash equals local SHA-256 of canonical JSON of state", () => {
  fc.assert(
    fc.property(
      arbDeterministicObject(2),
      (stateData) => {
        const state = stateData as NormalizedState;
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state,
          issuer: "iss",
          audience: "aud",
          keyId: "kid-1",
          ttlSeconds: 30,
          now: new Date(1_700_000_000_000),
        });

        assert.ok(result.ok);
        assert.equal(result.authorization.state_hash, localCanonicalHash(state));
      }
    )
  );
});

test("P3c – intent_hash and state_hash are independent: each binds to its own input, state hash is stable across intent changes", () => {
  fc.assert(
    fc.property(
      arbDeterministicObject(1),
      arbDeterministicObject(1),
      arbDeterministicObject(1),
      (params1, params2, stateData) => {
        const intent1 = makeIntent("tool", params1);
        const intent2 = makeIntent("tool", params2);
        const state = stateData as NormalizedState;
        const base = {
          receipt: makeReceipt() as never,
          state,
          issuer: "iss",
          audience: "aud",
          keyId: "k",
          ttlSeconds: 30,
          now: new Date(1_700_000_000_000),
        };

        const r1 = receiptToAuthorization({ ...base, intent: intent1 });
        const r2 = receiptToAuthorization({ ...base, intent: intent2 });

        assert.ok(r1.ok);
        assert.ok(r2.ok);

        // State hash must be stable when only intent changes.
        assert.equal(r1.authorization.state_hash, r2.authorization.state_hash);

        // Each intent_hash must equal the locally-computed hash for that intent.
        assert.equal(r1.authorization.intent_hash, localCanonicalHash(intent1));
        assert.equal(r2.authorization.intent_hash, localCanonicalHash(intent2));
      }
    )
  );
});

// ─── P4: Time derivation ──────────────────────────────────────────────────────

test("P4a – issued_at = floor(now.getTime() / 1000), expires_at = issued_at + ttlSeconds", () => {
  fc.assert(
    fc.property(
      arbValidDate(),
      arbPositiveSafeInt(),
      (now, ttlSeconds) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer: "iss",
          audience: "aud",
          keyId: "kid",
          ttlSeconds,
          now,
        });

        assert.ok(result.ok);
        const expectedIssuedAt = Math.floor(now.getTime() / 1000);
        assert.equal(result.authorization.issued_at, expectedIssuedAt);
        assert.equal(result.authorization.expires_at, expectedIssuedAt + ttlSeconds);
      }
    )
  );
});

test("P4b – default TTL is 30 seconds when ttlSeconds is omitted", () => {
  // Use a timestamp with a sub-second component to exercise the floor() branch.
  const now = new Date(1_700_000_050_500);  // .5s remainder → floor drops it
  const result = receiptToAuthorization({
    receipt: makeReceipt() as never,
    intent: makeIntent(),
    state: makeState(),
    issuer: "iss",
    audience: "aud",
    keyId: "kid",
    now,
    // ttlSeconds intentionally omitted → source default of 30 must apply
  });

  assert.ok(result.ok);
  const expectedIssuedAt = Math.floor(now.getTime() / 1000);  // 1700000050
  assert.equal(result.authorization.issued_at, expectedIssuedAt);
  assert.equal(result.authorization.expires_at, expectedIssuedAt + 30);
});

// ─── P5: Invalid TTL fails closed ─────────────────────────────────────────────
// The TTL check (step 5) is reached after: decision, issuer, audience, keyId,
// policy_matched, intent, state — all satisfied by the base fixture.

test("P5a – ttlSeconds = 0 → INVALID_TTL", () => {
  const result = receiptToAuthorization({
    receipt: makeReceipt() as never,
    intent: makeIntent(),
    state: makeState(),
    issuer: "iss",
    audience: "aud",
    keyId: "kid",
    ttlSeconds: 0,
    now: new Date(1_700_000_000_000),
  });
  assert.ok(!result.ok);
  assert.equal(result.code, "INVALID_TTL");
});

test("P5b – negative ttlSeconds → INVALID_TTL", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: Number.MIN_SAFE_INTEGER, max: -1 }),
      (ttlSeconds) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer: "iss",
          audience: "aud",
          keyId: "kid",
          ttlSeconds,
          now: new Date(1_700_000_000_000),
        });
        assert.ok(!result.ok);
        assert.equal(result.code, "INVALID_TTL");
      }
    )
  );
});

test("P5c – non-integer finite float ttlSeconds → INVALID_TTL", () => {
  fc.assert(
    fc.property(
      fc
        .float({ noNaN: true, noDefaultInfinity: true })
        .filter((n) => !Number.isInteger(n)),
      (ttlSeconds) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer: "iss",
          audience: "aud",
          keyId: "kid",
          ttlSeconds,
          now: new Date(1_700_000_000_000),
        });
        assert.ok(!result.ok);
        assert.equal(result.code, "INVALID_TTL");
      }
    )
  );
});

test("P5d – NaN / Infinity / -Infinity ttlSeconds → INVALID_TTL", () => {
  for (const ttlSeconds of [NaN, Infinity, -Infinity]) {
    const result = receiptToAuthorization({
      receipt: makeReceipt() as never,
      intent: makeIntent(),
      state: makeState(),
      issuer: "iss",
      audience: "aud",
      keyId: "kid",
      ttlSeconds,
      now: new Date(1_700_000_000_000),
    });
    assert.ok(!result.ok, `Expected failure for ttlSeconds=${ttlSeconds}`);
    assert.equal(result.code, "INVALID_TTL");
  }
});

// ─── P6: Invalid binding strings fail with the right code ────────────────────
// Validation order: decision (1) → issuer (2) → audience (3) → keyId (4).
// Each sub-test passes all earlier checks so the error code is deterministic.

test("P6a – empty issuer → INVALID_ISSUER", () => {
  fc.assert(
    fc.property(arbNonEmptyString(), arbNonEmptyString(), (audience, keyId) => {
      const result = receiptToAuthorization({
        receipt: makeReceipt() as never,
        intent: makeIntent(),
        state: makeState(),
        issuer: "",
        audience,
        keyId,
        now: new Date(1_700_000_000_000),
      });
      assert.ok(!result.ok);
      assert.equal(result.code, "INVALID_ISSUER");
    })
  );
});

test("P6b – empty audience → INVALID_AUDIENCE", () => {
  fc.assert(
    fc.property(arbNonEmptyString(), arbNonEmptyString(), (issuer, keyId) => {
      const result = receiptToAuthorization({
        receipt: makeReceipt() as never,
        intent: makeIntent(),
        state: makeState(),
        issuer,
        audience: "",
        keyId,
        now: new Date(1_700_000_000_000),
      });
      assert.ok(!result.ok);
      assert.equal(result.code, "INVALID_AUDIENCE");
    })
  );
});

test("P6c – empty keyId → INVALID_KEY_ID", () => {
  fc.assert(
    fc.property(arbNonEmptyString(), arbNonEmptyString(), (issuer, audience) => {
      const result = receiptToAuthorization({
        receipt: makeReceipt() as never,
        intent: makeIntent(),
        state: makeState(),
        issuer,
        audience,
        keyId: "",
        now: new Date(1_700_000_000_000),
      });
      assert.ok(!result.ok);
      assert.equal(result.code, "INVALID_KEY_ID");
    })
  );
});

// ─── P7: DENY receipt → INVALID_RECEIPT_DECISION ─────────────────────────────

test("P7 – receipt with decision DENY → INVALID_RECEIPT_DECISION", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      (issuer, audience, keyId) => {
        const receipt = makeReceipt({ decision: "DENY" });
        const result = receiptToAuthorization({
          receipt: receipt as never,
          intent: makeIntent(),
          state: makeState(),
          issuer,
          audience,
          keyId,
          now: new Date(1_700_000_000_000),
        });
        assert.ok(!result.ok);
        assert.equal(result.code, "INVALID_RECEIPT_DECISION");
      }
    )
  );
});

// ─── P8: Empty policy_matched → INVALID_POLICY_ID ────────────────────────────
// policy_matched is checked at step 5 (after issuer/audience/keyId), so error
// code is deterministic given valid issuer/audience/keyId in the fixture.

test("P8 – receipt.policy_matched = empty string → INVALID_POLICY_ID", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      (issuer, audience, keyId) => {
        const receipt = makeReceipt({ policy_matched: "" });
        const result = receiptToAuthorization({
          receipt: receipt as never,
          intent: makeIntent(),
          state: makeState(),
          issuer,
          audience,
          keyId,
          now: new Date(1_700_000_000_000),
        });
        assert.ok(!result.ok);
        assert.equal(result.code, "INVALID_POLICY_ID");
      }
    )
  );
});

// ─── P9: Invalid Date → INVALID_TIMESTAMP ────────────────────────────────────
// The timestamp check is at step 6 (after TTL). Since ttlSeconds is omitted,
// the default of 30 applies and passes, so INVALID_TIMESTAMP is the first error.

test("P9a – new Date(\"not-a-date\") → INVALID_TIMESTAMP", () => {
  const result = receiptToAuthorization({
    receipt: makeReceipt() as never,
    intent: makeIntent(),
    state: makeState(),
    issuer: "iss",
    audience: "aud",
    keyId: "kid",
    now: new Date("not-a-date"),
  });
  assert.ok(!result.ok);
  assert.equal(result.code, "INVALID_TIMESTAMP");
});

test("P9b – any invalid Date (NaN getTime) → INVALID_TIMESTAMP", () => {
  const invalidDates = [
    new Date(""),
    new Date("invalid"),
    new Date(NaN),
  ];
  for (const now of invalidDates) {
    const result = receiptToAuthorization({
      receipt: makeReceipt() as never,
      intent: makeIntent(),
      state: makeState(),
      issuer: "iss",
      audience: "aud",
      keyId: "kid",
      now,
    });
    assert.ok(!result.ok, `Expected failure for now=${String(now)}`);
    assert.equal(result.code, "INVALID_TIMESTAMP");
  }
});

// ─── P10: Signing payload shape ───────────────────────────────────────────────

test("P10a – authorization.signature.sig is an empty string placeholder", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      (issuer, audience, keyId) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer,
          audience,
          keyId,
          now: new Date(1_700_000_000_000),
        });

        assert.ok(result.ok);
        assert.equal(result.authorization.signature.alg, "ed25519");
        assert.equal(result.authorization.signature.kid, keyId);
        assert.equal(result.authorization.signature.sig, "");
      }
    )
  );
});

test("P10b – signingPayload.signature has no `sig` own property", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      (issuer, audience, keyId) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer,
          audience,
          keyId,
          now: new Date(1_700_000_000_000),
        });

        assert.ok(result.ok);
        assert.equal(result.signingPayload.signature.alg, "ed25519");
        assert.equal(result.signingPayload.signature.kid, keyId);
        // The sig field MUST be absent: bytes signed must not include the
        // placeholder empty string from the authorization payload.
        assert.ok(
          !Object.prototype.hasOwnProperty.call(result.signingPayload.signature, "sig"),
          "signingPayload.signature must not have own property 'sig'"
        );
      }
    )
  );
});

test("P10c – signingPayload fields equal authorization fields except for signature", () => {
  fc.assert(
    fc.property(
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbNonEmptyString(),
      arbPositiveSafeInt(),
      arbValidDate(),
      (issuer, audience, keyId, ttlSeconds, now) => {
        const result = receiptToAuthorization({
          receipt: makeReceipt() as never,
          intent: makeIntent(),
          state: makeState(),
          issuer,
          audience,
          keyId,
          ttlSeconds,
          now,
        });

        assert.ok(result.ok);
        const { authorization, signingPayload } = result;

        assert.equal(signingPayload.version, authorization.version);
        assert.equal(signingPayload.auth_id, authorization.auth_id);
        assert.equal(signingPayload.issuer, authorization.issuer);
        assert.equal(signingPayload.audience, authorization.audience);
        assert.equal(signingPayload.decision, authorization.decision);
        assert.equal(signingPayload.intent_hash, authorization.intent_hash);
        assert.equal(signingPayload.state_hash, authorization.state_hash);
        assert.equal(signingPayload.policy_id, authorization.policy_id);
        assert.equal(signingPayload.issued_at, authorization.issued_at);
        assert.equal(signingPayload.expires_at, authorization.expires_at);
        // Signature header fields must match; `sig` absence is asserted in P10b.
        assert.equal(signingPayload.signature.alg, authorization.signature.alg);
        assert.equal(signingPayload.signature.kid, authorization.signature.kid);
      }
    )
  );
});

// ─── P11: Null intent / state → INVALID_BINDING_INPUT ────────────────────────
// intent/state are checked at step 4 (after policy_matched, which is non-empty
// in the base fixture). Code is deterministic.

test("P11a – intent: null → INVALID_BINDING_INPUT (fail-closed)", () => {
  const result = receiptToAuthorization({
    receipt: makeReceipt() as never,
    intent: null as never,
    state: makeState(),
    issuer: "iss",
    audience: "aud",
    keyId: "kid",
    now: new Date(1_700_000_000_000),
  });
  assert.ok(!result.ok);
  assert.equal(result.code, "INVALID_BINDING_INPUT");
});

test("P11b – state: null → INVALID_BINDING_INPUT (fail-closed)", () => {
  const result = receiptToAuthorization({
    receipt: makeReceipt() as never,
    intent: makeIntent(),
    state: null as never,
    issuer: "iss",
    audience: "aud",
    keyId: "kid",
    now: new Date(1_700_000_000_000),
  });
  assert.ok(!result.ok);
  assert.equal(result.code, "INVALID_BINDING_INPUT");
});

test("P11c – primitive intent and state → INVALID_BINDING_INPUT (fail-closed)", () => {
  for (const bad of [42, "string", true, undefined]) {
    const intentResult = receiptToAuthorization({
      receipt: makeReceipt() as never,
      intent: bad as never,
      state: makeState(),
      issuer: "iss",
      audience: "aud",
      keyId: "kid",
      now: new Date(1_700_000_000_000),
    });
    assert.ok(!intentResult.ok, `intent=${JSON.stringify(bad)}: expected ok=false`);
    assert.equal(intentResult.code, "INVALID_BINDING_INPUT");

    const stateResult = receiptToAuthorization({
      receipt: makeReceipt() as never,
      intent: makeIntent(),
      state: bad as never,
      issuer: "iss",
      audience: "aud",
      keyId: "kid",
      now: new Date(1_700_000_000_000),
    });
    assert.ok(!stateResult.ok, `state=${JSON.stringify(bad)}: expected ok=false`);
    assert.equal(stateResult.code, "INVALID_BINDING_INPUT");
  }
});
