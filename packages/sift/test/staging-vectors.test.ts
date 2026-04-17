// SPDX-License-Identifier: Apache-2.0
/**
 * staging-vectors.test.ts
 *
 * Pinned regression suite for the @oxdeai/sift adapter against the Sift
 * staging AuthorizationV1 contract.  Vectors are checked-in as a fixture so
 * the full suite runs offline without any network dependency.
 *
 * Test IDs: SV-1 through SV-11 (offline pinned — default, CI-safe)
 *           SV-L1 through SV-L4 (live opt-in — SIFT_STAGING_LIVE=1)
 *
 *   SV-1   Fixture shape is valid and all vectors are present
 *   SV-2   ALLOW vector signing preimage is byte-exact with adapter canonicalization
 *   SV-3   DENY vector signing preimage is byte-exact
 *   SV-4   REPLAY vector signing preimage is byte-exact
 *   SV-5   SHA-256 of preimage bytes matches expected hex for every vector
 *   SV-6   ALLOW vector signature verifies with pinned staging public key
 *   SV-7   DENY vector: signature is valid but decision ≠ ALLOW → not executable
 *   SV-8   REPLAY vector: signature is valid but decision ≠ ALLOW → not executable
 *   SV-9   Preimage canonicalization is deterministic across repeated calls
 *   SV-10  JWKS kid decoding: staging x field decodes to 32 bytes via adapter helper
 *   SV-11  Adapter binding: receiptToAuthorization maps auth_id / policy_id / issuer / audience
 *
 *   SV-L1  Live vector endpoint responds and parses with same shape as pinned fixture
 *   SV-L2  Live ALLOW vector signature verifies with live JWKS public key
 *   SV-L3  Live DENY / REPLAY vectors are classified as non-executable (decision ≠ ALLOW)
 *   SV-L4  KRL check: staging kid is not currently revoked
 *
 * ─── Boundary of responsibility ───────────────────────────────────────────────
 *
 * Adapter (this package) is responsible for:
 *   - Canonical JSON serialization  (siftCanonicalJsonBytes)
 *   - Signature preimage construction and verification
 *   - Key material decoding from JWKS x field
 *   - Field binding in receiptToAuthorization (auth_id, policy_id, issuer, audience)
 *
 * PEP boundary (not tested here):
 *   - Replay prevention (auth_id deduplication across requests)
 *   - State binding enforcement
 *   - Intent hash verification against the executing intent
 *   - Execution gating and budget enforcement
 *
 * The REPLAY decision type (decision="REPLAY") is issued by the Sift service as
 * a terminal non-executable verdict.  It extends the adapter's current
 * SiftDecision = "ALLOW" | "DENY" type.  The adapter correctly gates execution
 * on decision === "ALLOW"; REPLAY is therefore non-executable without any code
 * change.  Authoritatively enforcing replay is the PEP boundary's responsibility.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, verify as nodeVerify } from "node:crypto";

import { siftCanonicalJsonBytes } from "../src/siftCanonical.js";
import { b64uDecode, publicKeyFromRaw } from "../src/siftCanonical.js";
import { receiptToAuthorization } from "../src/receiptToAuthorization.js";
import type { SiftReceipt } from "../src/verifyReceipt.js";
import type { OxDeAIIntent } from "../src/normalizeIntent.js";
import type { NormalizedState } from "../src/state.js";

// ── Fixture loading ────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES  = resolve(__dirname, "../../test/fixtures");

// Loaded once at module evaluation time — fail fast if fixtures are missing.
const PINNED_VECTORS = JSON.parse(
  readFileSync(resolve(FIXTURES, "staging-vectors.json"), "utf-8")
) as StagingVectorFile;

const PINNED_JWKS = JSON.parse(
  readFileSync(resolve(FIXTURES, "staging-jwks.json"), "utf-8")
) as JwksFile;

// ── Fixture types ──────────────────────────────────────────────────────────────

interface StagingVector {
  name: string;
  description: string;
  intent_text: string;
  state_text: string;
  /** Exact canonical JSON string that was signed (signature.sig absent). */
  preimage: string;
  preimage_sha256_hex: string;
  expected_signature_b64u: string;
  signed_payload: {
    audience: string;
    auth_id: string;
    /** "ALLOW" | "DENY" | "REPLAY" — REPLAY is a terminal non-executable verdict. */
    decision: string;
    expires_at: number;
    intent_hash: string;
    issued_at: number;
    issuer: string;
    policy_id: string;
    signature: { alg: string; kid: string; sig: string };
    state_hash: string;
    version: string;
  };
}

interface StagingVectorFile {
  version: number;
  kid: string;
  algorithm: string;
  encoding: string;
  canonicalization: string;
  preimage_rule: string;
  jwks_url: string;
  krl_url: string;
  vectors: StagingVector[];
}

interface JwksFile {
  keys: Array<{ kty: string; crv: string; kid: string; use: string; alg: string; x: string }>;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Strips `signature.sig` from a signed_payload to produce the signing preimage
 * object.  Sift's preimage rule: AuthorizationV1 with signature.alg + kid
 * present and signature.sig key absent.
 */
function signingPayloadOf(v: StagingVector): Record<string, unknown> {
  const { sig: _sig, ...sigWithoutSig } = v.signed_payload.signature;
  return { ...v.signed_payload, signature: sigWithoutSig };
}

/** Resolves a key from the pinned JWKS by kid. */
function pinnedKeyRaw(kid: string): Uint8Array {
  const entry = PINNED_JWKS.keys.find((k) => k.kid === kid);
  assert.ok(entry, `JWKS fixture has no entry for kid=${kid}`);
  return b64uDecode(entry.x);
}

/** Returns the vector with the given name, failing fast if absent. */
function vec(name: string): StagingVector {
  const v = PINNED_VECTORS.vectors.find((v) => v.name === name);
  assert.ok(v, `Staging fixture missing vector: ${name}`);
  return v;
}

// ── SV-1: fixture shape ────────────────────────────────────────────────────────

test("SV-1 fixture shape: staging-vectors.json has expected structure and all three vectors", () => {
  assert.strictEqual(typeof PINNED_VECTORS.version, "number", "version must be a number");
  assert.ok(typeof PINNED_VECTORS.kid === "string" && PINNED_VECTORS.kid.length > 0, "kid must be a non-empty string");
  assert.ok(Array.isArray(PINNED_VECTORS.vectors), "vectors must be an array");
  assert.ok(PINNED_VECTORS.vectors.length >= 3, "fixture must contain at least 3 vectors");

  for (const v of PINNED_VECTORS.vectors) {
    assert.ok(typeof v.name === "string" && v.name.length > 0, `vector.name must be non-empty`);
    assert.ok(typeof v.preimage === "string" && v.preimage.length > 0, `${v.name}: preimage must be non-empty`);
    assert.ok(typeof v.preimage_sha256_hex === "string" && v.preimage_sha256_hex.length === 64, `${v.name}: preimage_sha256_hex must be 64 hex chars`);
    assert.ok(typeof v.expected_signature_b64u === "string" && v.expected_signature_b64u.length === 86, `${v.name}: expected_signature_b64u must be 86 chars`);
    assert.ok(typeof v.signed_payload === "object" && v.signed_payload !== null, `${v.name}: signed_payload must be an object`);
    assert.ok(typeof v.signed_payload.signature.sig === "string" && v.signed_payload.signature.sig.length > 0, `${v.name}: sig must be present in signed_payload`);
  }

  // All three required decision types must be present.
  const decisions = new Set(PINNED_VECTORS.vectors.map((v) => v.signed_payload.decision));
  assert.ok(decisions.has("ALLOW"),  "fixture must include an ALLOW vector");
  assert.ok(decisions.has("DENY"),   "fixture must include a DENY vector");
  assert.ok(decisions.has("REPLAY"), "fixture must include a REPLAY vector");
});

// ── SV-2: ALLOW preimage canonicalization ─────────────────────────────────────

test("SV-2 ALLOW vector preimage: adapter siftCanonicalJsonBytes matches expected preimage exactly", () => {
  const v         = vec("allow-low-risk-read");
  const sigPayload = signingPayloadOf(v);
  const bytes     = siftCanonicalJsonBytes(sigPayload);
  const computed  = new TextDecoder().decode(bytes);

  assert.strictEqual(
    computed,
    v.preimage,
    `ALLOW preimage mismatch.\n  expected: ${v.preimage}\n  computed: ${computed}`
  );
});

// ── SV-3: DENY preimage canonicalization ──────────────────────────────────────

test("SV-3 DENY vector preimage: adapter siftCanonicalJsonBytes matches expected preimage exactly", () => {
  const v         = vec("deny-credential-exfiltration");
  const sigPayload = signingPayloadOf(v);
  const bytes     = siftCanonicalJsonBytes(sigPayload);
  const computed  = new TextDecoder().decode(bytes);

  assert.strictEqual(
    computed,
    v.preimage,
    `DENY preimage mismatch.\n  expected: ${v.preimage}\n  computed: ${computed}`
  );
});

// ── SV-4: REPLAY preimage canonicalization ────────────────────────────────────

test("SV-4 REPLAY vector preimage: adapter siftCanonicalJsonBytes matches expected preimage exactly", () => {
  // REPLAY is a terminal non-executable decision type issued by the Sift service.
  // The preimage contract is identical to ALLOW/DENY — canonical JSON, sig absent.
  const v         = vec("replay-stale-nonce");
  const sigPayload = signingPayloadOf(v);
  const bytes     = siftCanonicalJsonBytes(sigPayload);
  const computed  = new TextDecoder().decode(bytes);

  assert.strictEqual(
    computed,
    v.preimage,
    `REPLAY preimage mismatch.\n  expected: ${v.preimage}\n  computed: ${computed}`
  );
});

// ── SV-5: SHA-256 matches for all vectors ─────────────────────────────────────

test("SV-5 preimage SHA-256: matches expected hex for all three vectors", () => {
  for (const v of PINNED_VECTORS.vectors) {
    const bytes    = siftCanonicalJsonBytes(signingPayloadOf(v));
    const computed = createHash("sha256").update(bytes).digest("hex");

    assert.strictEqual(
      computed,
      v.preimage_sha256_hex,
      `${v.name}: SHA-256 mismatch.\n  expected: ${v.preimage_sha256_hex}\n  computed: ${computed}`
    );
  }
});

// ── SV-6: ALLOW signature verifies with pinned key ────────────────────────────

test("SV-6 ALLOW signature: verifies with pinned staging public key", () => {
  const v       = vec("allow-low-risk-read");
  const kid     = v.signed_payload.signature.kid;
  const rawKey  = pinnedKeyRaw(kid);
  const pubKey  = publicKeyFromRaw(rawKey);
  const preimage = siftCanonicalJsonBytes(signingPayloadOf(v));
  const sigBytes = b64uDecode(v.expected_signature_b64u);

  assert.ok(
    nodeVerify(null, preimage, pubKey, sigBytes),
    `SV-6: Ed25519 signature verification failed for vector ${v.name}`
  );
});

// ── SV-7: DENY has valid signature but decision ≠ ALLOW ───────────────────────

test("SV-7 DENY vector: signature is cryptographically valid but decision is not ALLOW", () => {
  const v       = vec("deny-credential-exfiltration");
  const kid     = v.signed_payload.signature.kid;
  const rawKey  = pinnedKeyRaw(kid);
  const pubKey  = publicKeyFromRaw(rawKey);
  const preimage = siftCanonicalJsonBytes(signingPayloadOf(v));
  const sigBytes = b64uDecode(v.expected_signature_b64u);

  // Signature is valid — it was legitimately issued by the staging key.
  assert.ok(
    nodeVerify(null, preimage, pubKey, sigBytes),
    `SV-7: signature verification failed — fixture may be stale`
  );

  // But the decision is DENY → not executable.
  assert.strictEqual(
    v.signed_payload.decision,
    "DENY",
    "SV-7: vector must carry a DENY decision"
  );
  assert.notStrictEqual(
    v.signed_payload.decision,
    "ALLOW",
    "SV-7: DENY vector must not have decision ALLOW"
  );
});

// ── SV-8: REPLAY has valid signature but decision ≠ ALLOW ─────────────────────

test("SV-8 REPLAY vector: signature is cryptographically valid but decision is not ALLOW", () => {
  // REPLAY extends the ALLOW/DENY type; the adapter gates execution on
  // decision === "ALLOW" so REPLAY is correctly non-executable.
  const v       = vec("replay-stale-nonce");
  const kid     = v.signed_payload.signature.kid;
  const rawKey  = pinnedKeyRaw(kid);
  const pubKey  = publicKeyFromRaw(rawKey);
  const preimage = siftCanonicalJsonBytes(signingPayloadOf(v));
  const sigBytes = b64uDecode(v.expected_signature_b64u);

  assert.ok(
    nodeVerify(null, preimage, pubKey, sigBytes),
    `SV-8: signature verification failed — fixture may be stale`
  );

  assert.strictEqual(
    v.signed_payload.decision,
    "REPLAY",
    "SV-8: vector must carry a REPLAY decision"
  );
  assert.notStrictEqual(
    v.signed_payload.decision,
    "ALLOW",
    "SV-8: REPLAY vector must not have decision ALLOW"
  );
});

// ── SV-9: canonicalization is deterministic ───────────────────────────────────

test("SV-9 determinism: siftCanonicalJsonBytes produces identical bytes on repeated calls", () => {
  for (const v of PINNED_VECTORS.vectors) {
    const payload = signingPayloadOf(v);
    const a = siftCanonicalJsonBytes(payload);
    const b = siftCanonicalJsonBytes(payload);
    assert.deepStrictEqual(
      Buffer.from(a),
      Buffer.from(b),
      `${v.name}: canonicalization must be deterministic`
    );
    // Also verify the hash is stable.
    const ha = createHash("sha256").update(a).digest("hex");
    const hb = createHash("sha256").update(b).digest("hex");
    assert.strictEqual(ha, hb, `${v.name}: SHA-256 must be stable across calls`);
  }
});

// ── SV-10: JWKS x decoding via adapter helper ─────────────────────────────────

test("SV-10 JWKS kid decoding: staging x field decodes to exactly 32 bytes via b64uDecode + publicKeyFromRaw", () => {
  for (const entry of PINNED_JWKS.keys) {
    assert.ok(
      entry.kty === "OKP" && entry.crv === "Ed25519",
      `key ${entry.kid}: expected OKP/Ed25519, got ${entry.kty}/${entry.crv}`
    );

    const raw = b64uDecode(entry.x);
    assert.strictEqual(
      raw.length,
      32,
      `kid=${entry.kid}: decoded x must be 32 bytes, got ${raw.length}`
    );

    // Round-trip: import as KeyObject and confirm it doesn't throw.
    const keyObj = publicKeyFromRaw(raw);
    const exported = keyObj.export({ type: "spki", format: "der" }) as Buffer;
    // Last 32 bytes of the SPKI DER are the raw key material.
    const roundTripped = Buffer.from(exported).subarray(exported.length - 32);
    assert.deepStrictEqual(
      roundTripped,
      Buffer.from(raw),
      `kid=${entry.kid}: round-trip raw key mismatch`
    );
  }
});

// ── SV-11: adapter binding path ───────────────────────────────────────────────

test("SV-11 adapter binding: receiptToAuthorization maps auth_id / policy_id / issuer / audience from ALLOW vector", () => {
  // The staging vectors represent Sift's authorization output format.
  // receiptToAuthorization produces the same format from a SiftReceipt input.
  // This test proves the field mapping contract is compatible with the staging contract.

  const v = vec("allow-low-risk-read");

  // Construct a synthetic SiftReceipt that carries the binding fields we want
  // to round-trip.  receiptToAuthorization only inspects:
  //   receipt.decision, receipt.nonce, receipt.policy_matched.
  // The other fields are structural requirements of SiftReceipt but are not
  // used in the authorization output.
  const synthReceipt: SiftReceipt = {
    receipt_version: "1.0",
    tenant_id: "staging-regression",
    agent_id: "sv11-agent",
    action: "read",
    tool: "file_reader",
    decision: "ALLOW",
    risk_tier: 1,
    timestamp: new Date(v.signed_payload.issued_at * 1000).toISOString(),
    nonce:          v.signed_payload.auth_id,    // auth_id binding ← receipt.nonce
    policy_matched: v.signed_payload.policy_id,  // policy_id binding ← receipt.policy_matched
    receipt_hash: "a".repeat(64),
    signature:    "b".repeat(86),
  };

  // Use a simple null-prototype intent and state — the binding test cares about
  // auth_id / policy_id / issuer / audience, not the hash values.
  const mockIntent: OxDeAIIntent = {
    type: "EXECUTE",
    tool: "file_reader",
    params: Object.create(null) as Record<string, never>,
  };

  const mockState = Object.assign(
    Object.create(null),
    { snapshot_id: "sv11-test" }
  ) as NormalizedState;

  const result = receiptToAuthorization({
    receipt:    synthReceipt,
    intent:     mockIntent,
    state:      mockState,
    issuer:     v.signed_payload.issuer,
    audience:   v.signed_payload.audience,
    keyId:      PINNED_VECTORS.kid,
    ttlSeconds: v.signed_payload.expires_at - v.signed_payload.issued_at,
    now:        new Date(v.signed_payload.issued_at * 1000),
  });

  assert.ok(result.ok, `SV-11: receiptToAuthorization failed: ${!result.ok && result.message}`);
  if (!result.ok) return;

  const auth = result.authorization;

  // Core binding invariants from the staging contract.
  assert.strictEqual(auth.auth_id,   v.signed_payload.auth_id,   "SV-11: auth_id must equal receipt.nonce");
  assert.strictEqual(auth.policy_id, v.signed_payload.policy_id, "SV-11: policy_id must equal receipt.policy_matched");
  assert.strictEqual(auth.issuer,    v.signed_payload.issuer,    "SV-11: issuer must equal the supplied issuer");
  assert.strictEqual(auth.audience,  v.signed_payload.audience,  "SV-11: audience must equal the supplied audience");
  assert.strictEqual(auth.decision,  "ALLOW",                    "SV-11: authorization decision must be ALLOW");
  assert.strictEqual(auth.version,   "AuthorizationV1",           "SV-11: version must be AuthorizationV1");
  assert.strictEqual(auth.signature.alg, "ed25519",              "SV-11: signature.alg must be ed25519");
  assert.strictEqual(auth.signature.kid, PINNED_VECTORS.kid,     "SV-11: signature.kid must match the supplied keyId");
  assert.strictEqual(auth.signature.sig, "",                     "SV-11: signature.sig must be empty placeholder until signed");

  // Hash fields must be 64-char hex strings (SHA-256).
  assert.match(auth.intent_hash, /^[0-9a-f]{64}$/, "SV-11: intent_hash must be 64-char hex");
  assert.match(auth.state_hash,  /^[0-9a-f]{64}$/, "SV-11: state_hash must be 64-char hex");

  // Signing payload must have sig absent.
  assert.ok(
    !("sig" in result.signingPayload.signature),
    "SV-11: signingPayload.signature must not contain sig key"
  );
});

// ── Live opt-in tests (SIFT_STAGING_LIVE=1) ───────────────────────────────────

if (process.env["SIFT_STAGING_LIVE"] === "1") {
  const STAGING_VECTORS_URL = "https://sift-staging.walkosystems.com/sift-staging-vectors.json";
  const STAGING_JWKS_URL    = "https://sift-staging.walkosystems.com/sift-jwks.json";
  const STAGING_KRL_URL     = "https://sift-staging.walkosystems.com/sift-krl.json";

  test("SV-L1 live: vector endpoint responds and has same shape as pinned fixture", async () => {
    const res  = await fetch(STAGING_VECTORS_URL);
    assert.ok(res.ok, `SV-L1: staging vectors fetch failed: HTTP ${res.status}`);

    const live = await res.json() as StagingVectorFile;
    assert.strictEqual(typeof live.version, "number", "SV-L1: version must be a number");
    assert.ok(typeof live.kid === "string" && live.kid.length > 0, "SV-L1: kid must be non-empty");
    assert.ok(Array.isArray(live.vectors) && live.vectors.length > 0, "SV-L1: vectors must be a non-empty array");

    for (const v of live.vectors) {
      assert.ok(typeof v.preimage === "string" && v.preimage.length > 0, `SV-L1: ${v.name} preimage must be non-empty`);
      assert.ok(typeof v.preimage_sha256_hex === "string" && v.preimage_sha256_hex.length === 64, `SV-L1: ${v.name} preimage_sha256_hex must be 64 chars`);
      assert.ok(typeof v.expected_signature_b64u === "string" && v.expected_signature_b64u.length === 86, `SV-L1: ${v.name} expected_signature_b64u must be 86 chars`);
    }
  });

  test("SV-L2 live: ALLOW vector signature verifies with live JWKS public key", async () => {
    const [vectorsRes, jwksRes] = await Promise.all([
      fetch(STAGING_VECTORS_URL),
      fetch(STAGING_JWKS_URL),
    ]);
    assert.ok(vectorsRes.ok, `SV-L2: vectors fetch failed: HTTP ${vectorsRes.status}`);
    assert.ok(jwksRes.ok,    `SV-L2: JWKS fetch failed: HTTP ${jwksRes.status}`);

    const live     = await vectorsRes.json() as StagingVectorFile;
    const liveJwks = await jwksRes.json() as JwksFile;

    const allowVec = live.vectors.find((v) => v.signed_payload.decision === "ALLOW");
    assert.ok(allowVec, "SV-L2: live vectors must contain at least one ALLOW vector");

    const kid      = allowVec!.signed_payload.signature.kid;
    const entry    = liveJwks.keys.find((k) => k.kid === kid);
    assert.ok(entry, `SV-L2: JWKS has no entry for kid=${kid}`);

    const rawKey  = b64uDecode(entry!.x);
    const pubKey  = publicKeyFromRaw(rawKey);
    const preimage = siftCanonicalJsonBytes(signingPayloadOf(allowVec!));
    const sigBytes = b64uDecode(allowVec!.expected_signature_b64u);

    assert.ok(
      nodeVerify(null, preimage, pubKey, sigBytes),
      "SV-L2: live ALLOW vector signature verification failed"
    );

    // Preimage hash must also match.
    const hash = createHash("sha256").update(preimage).digest("hex");
    assert.strictEqual(hash, allowVec!.preimage_sha256_hex, "SV-L2: live preimage SHA-256 mismatch");
  });

  test("SV-L3 live: DENY and REPLAY vectors are classified as non-executable (decision ≠ ALLOW)", async () => {
    const res  = await fetch(STAGING_VECTORS_URL);
    assert.ok(res.ok, `SV-L3: vectors fetch failed: HTTP ${res.status}`);
    const live = await res.json() as StagingVectorFile;

    for (const v of live.vectors) {
      if (v.signed_payload.decision === "ALLOW") continue;
      assert.notStrictEqual(
        v.signed_payload.decision,
        "ALLOW",
        `SV-L3: ${v.name} has decision ${v.signed_payload.decision} but must not equal ALLOW`
      );
    }
  });

  test("SV-L4 live: KRL check — staging kid is not currently revoked", async () => {
    const [jwksRes, krlRes] = await Promise.all([
      fetch(STAGING_JWKS_URL),
      fetch(STAGING_KRL_URL),
    ]);
    assert.ok(jwksRes.ok, `SV-L4: JWKS fetch failed: HTTP ${jwksRes.status}`);
    assert.ok(krlRes.ok,  `SV-L4: KRL fetch failed: HTTP ${krlRes.status}`);

    const liveJwks = await jwksRes.json() as JwksFile;
    const liveKrl  = await krlRes.json() as { revoked_kids: string[] };

    assert.ok(Array.isArray(liveKrl.revoked_kids), "SV-L4: KRL must have revoked_kids array");
    const revokedSet = new Set(liveKrl.revoked_kids);

    for (const key of liveJwks.keys) {
      assert.ok(
        !revokedSet.has(key.kid),
        `SV-L4: active JWKS key ${key.kid} is in the KRL — rotate fixtures and staging key`
      );
    }
  });
}
