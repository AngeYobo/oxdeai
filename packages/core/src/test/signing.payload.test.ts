import test from "node:test";
import assert from "node:assert/strict";
import { authorizationSigningPayload, envelopeSigningPayload } from "../verification/index.js";
import { signatureInput, SIGNING_DOMAINS } from "../crypto/signatures.js";

test("authorization signing payload bytes are deterministic", () => {
  const auth = {
    auth_id: "f".repeat(64),
    issuer: "issuer-A",
    audience: "rp-A",
    intent_hash: "a".repeat(64),
    state_hash: "b".repeat(64),
    policy_id: "c".repeat(64),
    decision: "ALLOW" as const,
    issued_at: 1000,
    expiry: 1060,
    alg: "Ed25519" as const,
    kid: "2026-01",
    signature: "sig",
    nonce: "1",
    capability: "PAYMENT"
  };

  const p1 = authorizationSigningPayload(auth);
  const p2 = authorizationSigningPayload({ ...auth, signature: "different" });
  assert.deepEqual(p1, p2);

  const b1 = signatureInput(SIGNING_DOMAINS.AUTH_V1, p1);
  const b2 = signatureInput(SIGNING_DOMAINS.AUTH_V1, p2);
  assert.deepEqual(Buffer.from(b1), Buffer.from(b2));
});

test("envelope signing payload bytes are deterministic", () => {
  const base = {
    formatVersion: 1 as const,
    snapshot: new Uint8Array([1, 2, 3]),
    events: [
      {
        type: "STATE_CHECKPOINT" as const,
        stateHash: "a".repeat(64),
        timestamp: 1,
        policyId: "p1"
      }
    ],
    issuer: "issuer-A",
    alg: "Ed25519" as const,
    kid: "2026-01",
    signature: "sig"
  };

  const p1 = envelopeSigningPayload(base);
  const p2 = envelopeSigningPayload({ ...base, signature: "other" });
  assert.deepEqual(p1, p2);

  const b1 = signatureInput(SIGNING_DOMAINS.ENVELOPE_V1, p1);
  const b2 = signatureInput(SIGNING_DOMAINS.ENVELOPE_V1, p2);
  assert.deepEqual(Buffer.from(b1), Buffer.from(b2));
});
