import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/index.js";
import type { KeySet } from "../types/keyset.js";

const TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const TEST_KEYSET: KeySet = {
  issuer: "issuer-A",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.publicKey }]
};

function makeAuth() {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: 1000,
      expiry: 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
}

test("ok: valid signed authorization", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    expectedPolicyId: "c".repeat(64),
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
});

test("invalid: tampered authorization field", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, state_hash: "d".repeat(64) }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("invalid: unknown kid", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, kid: "missing" }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});

test("invalid: strict mode without trustedKeySets fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("invalid: strict mode with empty trustedKeySets array fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict", trustedKeySets: [] });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("ok: strict mode with trustedKeySets passes the guard", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    mode: "strict",
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
  assert.equal(out.violations.filter((v) => v.code === "TRUSTED_KEYSETS_REQUIRED").length, 0);
});

test("invalid: unsupported alg", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, alg: "Unknown" as any }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ALG_UNSUPPORTED"));
});
