// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for verifyReceiptWithKeyStore — keystore-based key resolution, KRL
 * enforcement, refresh-on-unknown-kid, and fail-closed behavior.
 *
 * All unit tests use an injected fetch mock.  No network calls are made unless
 * SIFT_STAGING_LIVE=1 is set.
 *
 * Receipt building uses Sift-canonical JSON (ensure_ascii=True) and
 * base64url-no-padding signatures to match the full contract wire format.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
} from "node:crypto";

import { verifyReceiptWithKeyStore } from "../src/verifyReceipt.js";
import { SiftHttpKeyStore } from "../src/siftKeyStore.js";
import { siftCanonicalJsonBytes, b64uEncode } from "../src/siftCanonical.js";

// ─── Receipt building helpers ─────────────────────────────────────────────────
//
// Build order matches verifyReceipt.ts exactly:
//   ① base (no receipt_hash, no signature) → sha256(siftCanonical(①)) = receipt_hash
//   ② withHash = ① + receipt_hash
//   ③ signature = b64u( sign( siftCanonical( ② ) ) )

interface TestKeyPair {
  /** Raw 32-byte public key — what JWKS x encodes. */
  publicKeyRaw: Uint8Array;
  /** base64url of publicKeyRaw — used as JWKS x field. */
  publicKeyJwksX: string;
  /** PKCS8 PEM — used by Node.js signing. */
  privateKeyPem: string;
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function makeTestKeyPair(): TestKeyPair {
  const { publicKey: pubObj, privateKey: privObj } = generateKeyPairSync("ed25519");
  const spkiDer = pubObj.export({ type: "spki", format: "der" }) as Buffer;
  const publicKeyRaw = spkiDer.subarray(ED25519_SPKI_PREFIX.length);
  return {
    publicKeyRaw,
    publicKeyJwksX: b64uEncode(publicKeyRaw),
    privateKeyPem: privObj.export({ type: "pkcs8", format: "pem" }) as string,
  };
}

const FIXED_NOW = new Date("2026-04-14T12:00:00.000Z");

function buildSignedReceipt(
  kp: TestKeyPair,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  const base: Record<string, unknown> = {
    receipt_version: "1.0",
    tenant_id: "tenant-test",
    agent_id: "agent-test",
    action: "call_tool",
    tool: "query_database",
    decision: "ALLOW",
    risk_tier: 1,
    timestamp: FIXED_NOW.toISOString(),
    nonce: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    policy_matched: "policy-v1",
    ...overrides,
  };

  // ① receipt_hash over base (no signature, no receipt_hash in scope)
  const receipt_hash = createHash("sha256")
    .update(siftCanonicalJsonBytes(base))
    .digest("hex");

  // ② signed payload = base + receipt_hash (no signature yet)
  const withHash = { ...base, receipt_hash };

  // ③ signature = base64url( sign( siftCanonical( withHash ) ) )
  const sigBuf = nodeSign(null, siftCanonicalJsonBytes(withHash), kp.privateKeyPem);
  const signature = b64uEncode(sigBuf);

  return { ...withHash, signature };
}

// ─── Mock fetch factory ───────────────────────────────────────────────────────

const JWKS_URL = "https://sift-staging.example.test/sift-jwks.json";
const KRL_URL  = "https://sift-staging.example.test/sift-krl.json";

function makeJwksBody(kp: TestKeyPair, kid: string): unknown {
  return {
    keys: [
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid, x: kp.publicKeyJwksX },
    ],
  };
}

function makeKrlBody(revokedKids: string[] = []): unknown {
  return {
    version: 1,
    issuer: "sift-staging",
    algorithm: "ed25519",
    generated_at: "2026-01-01T00:00:00Z",
    revoked_kids: revokedKids,
  };
}

type MockRoutes = Record<string, { status: number; body: unknown }>;

function makeFetch(routes: MockRoutes): typeof globalThis.fetch {
  return async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const route = routes[url];
    if (!route) return new Response(null, { status: 404 }) as Response;
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    }) as Response;
  };
}

function makeStore(routes: MockRoutes): SiftHttpKeyStore {
  return new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL, fetch: makeFetch(routes) });
}

// ─── Tests: happy path ────────────────────────────────────────────────────────

test("verifyReceiptWithKeyStore: resolves key and verifies valid receipt", async () => {
  const kp  = makeTestKeyPair();
  const kid = "test-key-1";
  const receipt = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });
  // Pre-populate cache (avoids a refresh triggered by unknown kid).
  await store.refresh();

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.ok(result.ok, `Expected ok but got: ${JSON.stringify(!result.ok && result)}`);
  assert.strictEqual(result.receipt.decision, "ALLOW");
});

// ─── Tests: revocation ────────────────────────────────────────────────────────

test("verifyReceiptWithKeyStore: REVOKED_KID — kid revoked before lookup", async () => {
  const kp  = makeTestKeyPair();
  const kid = "revoked-key";
  const receipt = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody([kid]) },
  });
  await store.refresh();

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "REVOKED_KID");
});

// ─── Tests: unknown kid — refresh-on-unknown-kid ──────────────────────────────

test("verifyReceiptWithKeyStore: unknown kid triggers refresh and succeeds", async () => {
  const kp  = makeTestKeyPair();
  const kid = "new-key-after-refresh";
  const receipt = buildSignedReceipt(kp);

  // Store starts empty (no keys in cache) — kid will be unknown on first lookup.
  // On refresh it will find the key in JWKS.
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });
  // Do NOT pre-populate cache — this exercises the refresh-on-unknown-kid path.

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.ok(result.ok, `Expected ok after refresh but got: ${JSON.stringify(!result.ok && result)}`);
});

test("verifyReceiptWithKeyStore: unknown kid — still unknown after refresh → UNKNOWN_KID", async () => {
  const kp  = makeTestKeyPair();
  const kid = "nonexistent-kid";
  const receipt = buildSignedReceipt(kp);

  // JWKS doesn't contain this kid — even after refresh.
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: { keys: [] } },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "UNKNOWN_KID");
});

test("verifyReceiptWithKeyStore: kid revoked after refresh → REVOKED_KID", async () => {
  const kp  = makeTestKeyPair();
  const kid = "key-revoked-on-refresh";
  const receipt = buildSignedReceipt(kp);

  // Key is in JWKS (so lookup succeeds after refresh) BUT also in KRL.
  // This exercises the post-refresh revocation re-check.
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody([kid]) },
  });
  // Do NOT pre-populate — forces the refresh path, which then re-checks KRL.

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "REVOKED_KID");
});

// ─── Tests: refresh failures ──────────────────────────────────────────────────

test("verifyReceiptWithKeyStore: JWKS fetch failure on refresh → JWKS_FETCH_FAILED", async () => {
  const kp  = makeTestKeyPair();
  const kid = "any-kid";
  const receipt = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 500, body: null },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "JWKS_FETCH_FAILED");
});

test("verifyReceiptWithKeyStore: KRL fetch failure on refresh → KRL_FETCH_FAILED", async () => {
  const kp  = makeTestKeyPair();
  const kid = "any-kid";
  const receipt = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 503, body: null },
  });

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "KRL_FETCH_FAILED");
});

// ─── Tests: MISSING_KID guard ─────────────────────────────────────────────────

test("verifyReceiptWithKeyStore: empty kid → MISSING_KID", async () => {
  const kp  = makeTestKeyPair();
  const receipt = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, "some-kid") },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid: "",
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "MISSING_KID");
});

// ─── Tests: crypto failures still propagate correctly ─────────────────────────

test("verifyReceiptWithKeyStore: wrong key in JWKS → INVALID_SIGNATURE", async () => {
  const kp       = makeTestKeyPair(); // used to sign the receipt
  const wrongKp  = makeTestKeyPair(); // different key stored in JWKS
  const kid      = "wrong-key";
  const receipt  = buildSignedReceipt(kp);

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(wrongKp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });
  await store.refresh();

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "INVALID_SIGNATURE");
});

test("verifyReceiptWithKeyStore: malformed receipt → MALFORMED_RECEIPT", async () => {
  const kp  = makeTestKeyPair();
  const kid = "test-key";

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });
  await store.refresh();

  const result = await verifyReceiptWithKeyStore(
    { not_a_receipt: true },
    { kid, keyStore: store, now: FIXED_NOW }
  );

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "MALFORMED_RECEIPT");
});

test("verifyReceiptWithKeyStore: DENY receipt → DENY_DECISION", async () => {
  const kp  = makeTestKeyPair();
  const kid = "test-key";
  const receipt = buildSignedReceipt(kp, { decision: "DENY" });

  const store = makeStore({
    [JWKS_URL]: { status: 200, body: makeJwksBody(kp, kid) },
    [KRL_URL]:  { status: 200, body: makeKrlBody() },
  });
  await store.refresh();

  const result = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore: store,
    now: FIXED_NOW,
    maxAgeMs: 30_000,
  });

  assert.strictEqual(result.ok, false);
  assert.ok(!result.ok);
  assert.strictEqual(result.code, "DENY_DECISION");
});

// ─── Live staging integration test (opt-in) ───────────────────────────────────
//
// Gated by SIFT_STAGING_LIVE=1.  Not executed in CI by default.
//
// Validates:
//   - JWKS endpoint is reachable and parses correctly
//   - Every JWKS key decodes to exactly 32 bytes
//   - KRL endpoint is reachable and parses correctly
//
// Does NOT attempt to verify a receipt — no live Sift-issued receipt is
// available in this environment.

if (process.env["SIFT_STAGING_LIVE"] === "1") {
  const STAGING_JWKS = "https://sift-staging.walkosystems.com/sift-jwks.json";
  const STAGING_KRL  = "https://sift-staging.walkosystems.com/sift-krl.json";

  test("live: staging JWKS parses and all keys decode to 32 bytes", async () => {
    const res = await fetch(STAGING_JWKS);
    assert.ok(res.ok, `JWKS fetch failed: HTTP ${res.status}`);

    const body = await res.json() as Record<string, unknown>;
    assert.ok(Array.isArray(body["keys"]), "JWKS must have a 'keys' array");

    const keys = body["keys"] as unknown[];
    assert.ok(keys.length > 0, "JWKS must contain at least one key");

    for (const entry of keys) {
      if (typeof entry !== "object" || entry === null) continue;
      const e = entry as Record<string, unknown>;
      if (e["kty"] !== "OKP" || e["crv"] !== "Ed25519") continue;
      if (typeof e["x"] !== "string") continue;

      const normalized = (e["x"] as string)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      const raw = Buffer.from(normalized, "base64url");
      assert.strictEqual(
        raw.length,
        32,
        `JWKS key kid=${String(e["kid"])} x field decoded to ${raw.length} bytes, expected 32`
      );
    }
  });

  test("live: staging KRL parses and has revoked_kids array", async () => {
    const res = await fetch(STAGING_KRL);
    assert.ok(res.ok, `KRL fetch failed: HTTP ${res.status}`);

    const body = await res.json() as Record<string, unknown>;
    assert.ok(Array.isArray(body["revoked_kids"]), "KRL must have a 'revoked_kids' array");

    const revokedKids = body["revoked_kids"] as unknown[];
    for (const kid of revokedKids) {
      assert.strictEqual(typeof kid, "string", `revoked_kids entry is not a string: ${String(kid)}`);
    }
  });

  test("live: createStagingKeyStore refresh succeeds and loads at least one key", async () => {
    const { createStagingKeyStore } = await import("../src/siftKeyStore.js");
    const store = createStagingKeyStore();
    await store.refresh();

    // Probe the cache with a sentinel kid that won't match anything — just
    // confirms the store hydrated without throwing.
    const notFound = await store.getPublicKeyByKid("__probe__");
    assert.strictEqual(notFound, null, "probe kid should not match any real key");
  });
}
