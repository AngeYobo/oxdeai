// SPDX-License-Identifier: Apache-2.0
/**
 * Contract vector test — byte-for-byte preimage and signature verification.
 *
 * Verifies that the local canonicalization, ensure_ascii behavior, and
 * Ed25519 signing pipeline matches the Sift staging contract:
 *
 *   1. Canonical JSON with ensure_ascii=True behavior (Python equivalent).
 *   2. Signing preimage: AuthorizationV1 signing payload with signature.sig
 *      intentionally absent — the correct preimage per the contract.
 *   3. JWKS x: base64url-no-padding → raw 32-byte Ed25519 public key.
 *   4. Signature: base64url-no-padding Ed25519 over canonical preimage bytes.
 *
 * Key material: RFC 8037 Appendix A test vector — deterministic across runs.
 * No network calls.  All values are inline constants.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

// ─── RFC 8037 Appendix A — Ed25519 JWK test vector ───────────────────────────
//
// Source: https://www.rfc-editor.org/rfc/rfc8037#appendix-A
// These are fixed public constants from the RFC; using them makes every
// assertion in this file deterministic without pre-generating keys.
//
//   d  (private seed, base64url-no-padding, 32 bytes decoded)
//   x  (public key,   base64url-no-padding, 32 bytes decoded)

const RFC8037_D    = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const RFC8037_X    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID  = "key-rfc8037";

// ─── alg literal disambiguation ───────────────────────────────────────────────
//
// TWO DISTINCT SURFACES — MUST NOT BE CONFLATED:
//
//   "EdDSA"   — JWKS metadata label (RFC 8037 §2, OKP key-discovery tooling).
//               Appears in the JWKS entry: { "kty": "OKP", "alg": "EdDSA", ... }
//               It is NEVER included in an AuthorizationV1 signed payload.
//
//   "ed25519" — Runtime literal included in the AuthorizationV1 signing payload.
//               Defined in AuthorizationV1Payload.signature.alg as the literal
//               type "ed25519" (lowercase). MUST appear verbatim in the preimage.
//
// Consequence: changing "ed25519" to "EdDSA" in the signing payload produces
// different canonical bytes → a different signature → PEP verification fails.
// There is no normalization or case-folding of the alg field.
// See regression tests C-A and C-B at the bottom of this file.

// ─── Worked example: AuthorizationV1 signing payload ─────────────────────────
//
// This is the exact object that would be handed to the signer.
// signature.sig is absent — that absence is the signing preimage contract.
// signature.alg MUST be "ed25519" (the runtime literal, lowercase).
// All string values are ASCII so the ensure_ascii pass is a no-op here;
// the ensure_ascii tests below use separate non-ASCII payloads.

const EXAMPLE_SIGNING_PAYLOAD = {
  version:     "1",
  auth_id:     "d0000000-0000-0000-0000-000000000001",
  issuer:      "sift.example.local",
  audience:    "pep.example.local",
  decision:    "ALLOW",
  intent_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  state_hash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  policy_id:   "policy-v1",
  issued_at:   1700000000,
  expires_at:  1700000030,
  signature: {
    alg: "ed25519",   // runtime literal (lowercase) — NOT the JWKS "EdDSA" label
    kid: RFC8037_KID,
  },
} as const;

// ─── Expected canonical JSON (hand-computed) ──────────────────────────────────
//
// Rules applied:
//   • Keys sorted lexicographically at every object level
//   • No whitespace separators
//   • Non-ASCII code units escaped as \uXXXX (ensure_ascii=True)
//   • All values above are ASCII so no escaping occurs in this vector
//
// Top-level key order (verified):
//   audience < auth_id < decision < expires_at < intent_hash < issued_at
//   < issuer < policy_id < signature < state_hash < version
//
// signature key order: alg < kid

const EXPECTED_CANONICAL_JSON =
  '{"audience":"pep.example.local",' +
  '"auth_id":"d0000000-0000-0000-0000-000000000001",' +
  '"decision":"ALLOW",' +
  '"expires_at":1700000030,' +
  '"intent_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",' +
  '"issued_at":1700000000,' +
  '"issuer":"sift.example.local",' +
  '"policy_id":"policy-v1",' +
  '"signature":{"alg":"ed25519","kid":"key-rfc8037"},' +
  '"state_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",' +
  '"version":"1"}';

// ─── Canonicalization with ensure_ascii ──────────────────────────────────────

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

function canonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "string") return value as JsonValue;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite number: ${String(value)}`);
    return value;
  }
  if (Array.isArray(value)) return (value as unknown[]).map(canonicalize);
  if (typeof value === "object") {
    const keys = Object.keys(value as object).sort();
    const out = Object.create(null) as { [k: string]: JsonValue };
    for (const k of keys) out[k] = canonicalize((value as Record<string, unknown>)[k]);
    return out;
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

/**
 * Serializes `value` to canonical JSON with ensure_ascii=True behavior,
 * matching Python's:
 *   json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True)
 *
 * Every UTF-16 code unit outside 0x00–0x7F is escaped as \uXXXX.
 * For supplementary characters (U+10000+), JavaScript represents them as two
 * surrogate code units (U+D800–U+DFFF), each of which is individually escaped
 * — producing the same \uHHHH\uLLLL output as Python's ensure_ascii=True.
 */
function canonicalJsonEnsureAscii(value: unknown): string {
  const raw = JSON.stringify(canonicalize(value));
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code > 0x7f) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += raw[i];
    }
  }
  return out;
}

/** Returns the UTF-8 byte representation of `str` as a Buffer. */
function toUtf8(str: string): Buffer {
  return Buffer.from(str, "utf-8");
}

// ─── base64url helpers ────────────────────────────────────────────────────────

/** Decodes a base64url-no-padding string to a Buffer. */
function fromB64U(b64u: string): Buffer {
  const padded = b64u + "=".repeat((4 - (b64u.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Encodes a Buffer to base64url-no-padding (no +, /, or = characters). */
function toB64U(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ─── DER wrappers for raw Ed25519 key material ────────────────────────────────
//
// Ed25519 SPKI  (public key):  30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
// Ed25519 PKCS8 (private key): 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
//
// The OID 1.3.101.112 encodes as: 06 03 2b 65 70

const SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");   // 12 bytes
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex"); // 16 bytes

/** Creates a Node.js KeyObject from a base64url-encoded raw Ed25519 private seed. */
function privateKeyFromB64U(d: string): ReturnType<typeof createPrivateKey> {
  const seed = fromB64U(d);
  assert.strictEqual(seed.length, 32, `Ed25519 private seed must be 32 bytes, got ${seed.length}`);
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Creates a Node.js KeyObject from a base64url-encoded raw Ed25519 public key (JWKS x). */
function publicKeyFromB64U(x: string): ReturnType<typeof createPublicKey> {
  const raw = fromB64U(x);
  assert.strictEqual(raw.length, 32, `Ed25519 public key must be 32 bytes, got ${raw.length}`);
  const der = Buffer.concat([SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test("contract-vector: ensure_ascii escapes U+00E9 (é) as \\u00e9", () => {
  // Python: json.dumps({"msg": "café"}, ..., ensure_ascii=True) → '{"msg": "caf\\u00e9"}'
  // (minified, sorted keys — same result)
  const actual = canonicalJsonEnsureAscii({ msg: "caf\u00e9" });
  assert.strictEqual(actual, '{"msg":"caf\\u00e9"}');
});

test("contract-vector: ensure_ascii escapes U+0100 (Ā) as \\u0100", () => {
  const actual = canonicalJsonEnsureAscii({ k: "\u0100" });
  assert.strictEqual(actual, '{"k":"\\u0100"}');
});

test("contract-vector: ensure_ascii encodes U+1F600 (😀) as surrogate pair \\ud83d\\ude00", () => {
  // Matches Python's ensure_ascii=True behavior for supplementary characters:
  // code point U+1F600 → UTF-16 surrogates D83D + DE00 → each escaped individually.
  const actual = canonicalJsonEnsureAscii({ k: "\u{1F600}" });
  assert.strictEqual(actual, '{"k":"\\ud83d\\ude00"}');
});

test("contract-vector: preimage bytes match expected canonical JSON exactly", () => {
  const computed = canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD);

  if (computed !== EXPECTED_CANONICAL_JSON) {
    const cBytes = toUtf8(computed);
    const eBytes = toUtf8(EXPECTED_CANONICAL_JSON);
    // Find the first byte that diverges so the failure message is actionable.
    const minLen = Math.min(cBytes.length, eBytes.length);
    let firstDiff = -1;
    for (let i = 0; i < minLen; i++) {
      if (cBytes[i] !== eBytes[i]) { firstDiff = i; break; }
    }
    const diffMsg =
      firstDiff >= 0
        ? `First differing byte at offset ${firstDiff}: ` +
          `expected 0x${eBytes[firstDiff].toString(16).padStart(2, "0")} ` +
          `('${String.fromCharCode(eBytes[firstDiff])}'), ` +
          `got 0x${cBytes[firstDiff].toString(16).padStart(2, "0")} ` +
          `('${String.fromCharCode(cBytes[firstDiff])}')`
        : `Length mismatch: expected ${eBytes.length} bytes, got ${cBytes.length} bytes`;

    assert.fail(
      `Preimage mismatch.\n` +
      `  Expected (${eBytes.length} B): ${EXPECTED_CANONICAL_JSON}\n` +
      `  Computed (${cBytes.length} B): ${computed}\n` +
      `  ${diffMsg}`
    );
  }
});

test("contract-vector: JWKS x (base64url) decodes to 32-byte raw key", () => {
  const raw = fromB64U(RFC8037_X);
  assert.strictEqual(raw.length, 32);
  // Reconstruct via DER and export back as raw to confirm round-trip.
  const keyObj = publicKeyFromB64U(RFC8037_X);
  const exported = keyObj.export({ type: "spki", format: "der" }) as Buffer;
  assert.deepStrictEqual(
    exported.subarray(SPKI_PREFIX.length),
    raw,
    "Exported raw public key bytes do not match decoded x value"
  );
});

test("contract-vector: base64url-decoded JWKS x verifies Ed25519 signature over canonical preimage", () => {
  // 1. Build the preimage bytes.
  const preimage = toUtf8(canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD));

  // 2. Sign with the RFC 8037 private key.
  //    Ed25519 is deterministic: same key + same message → always same signature.
  const privKey = privateKeyFromB64U(RFC8037_D);
  const sigBuf  = nodeSign(null, preimage, privKey);

  // 3. The signature must be exactly 64 bytes.
  assert.strictEqual(sigBuf.length, 64, "Ed25519 signature must be 64 bytes");

  // 4. Encode as base64url-no-padding (contract format).
  const sigB64U = toB64U(sigBuf);
  assert.ok(
    !/[+/=]/.test(sigB64U),
    `Signature contains non-base64url characters: ${sigB64U}`
  );

  // 5. Verify using only the raw public key decoded from the JWKS x field.
  //    This is the full contract pipeline: base64url x → raw 32 bytes → verify.
  const pubKey   = publicKeyFromB64U(RFC8037_X);
  const sigBytes = fromB64U(sigB64U);
  const ok = nodeVerify(null, preimage, pubKey, sigBytes);
  assert.ok(ok, "Signature verification failed — preimage or key material mismatch");
});

test("contract-vector: mutated preimage fails verification", () => {
  const preimage = toUtf8(canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD));
  const privKey  = privateKeyFromB64U(RFC8037_D);
  const pubKey   = publicKeyFromB64U(RFC8037_X);
  const sig      = nodeSign(null, preimage, privKey);

  // Flip one bit in the preimage — verification must reject it.
  const mutated = Buffer.from(preimage);
  mutated[0] ^= 0x01;
  assert.strictEqual(
    nodeVerify(null, mutated, pubKey, sig),
    false,
    "Verification should fail on a mutated preimage"
  );
});

test("contract-vector: correct preimage fails with wrong public key", () => {
  const preimage = toUtf8(canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD));
  const privKey  = privateKeyFromB64U(RFC8037_D);
  const sig      = nodeSign(null, preimage, privKey);

  // Verify with an unrelated freshly-generated public key — must fail.
  const { publicKey: wrongPub } = generateKeyPairSync("ed25519");
  assert.strictEqual(
    nodeVerify(null, preimage, wrongPub, sig),
    false,
    "Verification should fail with an unrelated public key"
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// C-A / C-B  alg-literal regression — ed25519 vs EdDSA
//
// These tests lock in the invariant that the alg field is included verbatim in
// the canonical bytes and that its exact casing determines the signature.
//
// C-A (must pass): alg="ed25519" (production literal) → sign → verify → OK
// C-B (must fail): sign over alg="EdDSA" bytes, verify against alg="ed25519"
//                  bytes → FAIL because the preimages are different byte strings
//
// "EdDSA" is the JWKS metadata label (RFC 8037 OKP key-discovery).
// "ed25519" is the runtime literal in AuthorizationV1.signature.alg.
// They MUST NOT be conflated. There is no normalization or case-folding.
// ═══════════════════════════════════════════════════════════════════════════════

test("C-A [regression]: alg=\"ed25519\" in signing payload produces a verifiable signature", () => {
  // EXAMPLE_SIGNING_PAYLOAD.signature.alg === "ed25519" (the production runtime literal).
  // This is the correct canonical preimage for AuthorizationV1.
  const privKey  = privateKeyFromB64U(RFC8037_D);
  const pubKey   = publicKeyFromB64U(RFC8037_X);
  const preimage = toUtf8(canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD));
  const sig      = nodeSign(null, preimage, privKey);

  assert.ok(
    nodeVerify(null, preimage, pubKey, sig),
    'alg="ed25519" (runtime literal) MUST produce a verifiable signature'
  );

  // Confirm the alg field appears verbatim as "ed25519" in the canonical bytes.
  const canonicalStr = canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD);
  assert.ok(
    canonicalStr.includes('"alg":"ed25519"'),
    `Canonical preimage MUST contain "alg":"ed25519" verbatim. Got: ${canonicalStr}`
  );
  assert.ok(
    !canonicalStr.includes('"alg":"EdDSA"'),
    `Canonical preimage MUST NOT contain "alg":"EdDSA" in any form`
  );
});

test("C-B [regression]: signature over alg=\"EdDSA\" preimage MUST NOT verify against alg=\"ed25519\" preimage", () => {
  // Construct the WRONG payload that a misimplemented language adapter would produce:
  // using the JWKS metadata label "EdDSA" instead of the runtime literal "ed25519".
  // Spreading EXAMPLE_SIGNING_PAYLOAD and overriding signature.alg is the safest
  // way to produce the wrong variant without modifying the shared constant.
  const wrongPayload = {
    ...EXAMPLE_SIGNING_PAYLOAD,
    signature: {
      alg: "EdDSA",       // WRONG — JWKS label, not the runtime literal
      kid: RFC8037_KID,
    },
  };

  const privKey         = privateKeyFromB64U(RFC8037_D);
  const pubKey          = publicKeyFromB64U(RFC8037_X);

  // Sign over the WRONG preimage (EdDSA bytes).
  const wrongPreimage   = toUtf8(canonicalJsonEnsureAscii(wrongPayload));
  const sigOverWrong    = nodeSign(null, wrongPreimage, privKey);

  // The CORRECT production preimage uses the "ed25519" literal.
  const correctPreimage = toUtf8(canonicalJsonEnsureAscii(EXAMPLE_SIGNING_PAYLOAD));

  // The two preimages MUST be byte-distinct — "EdDSA" ≠ "ed25519".
  assert.notDeepStrictEqual(
    wrongPreimage,
    correctPreimage,
    'Preimage with alg="EdDSA" and preimage with alg="ed25519" MUST differ'
  );

  // A signature computed over the EdDSA preimage MUST NOT verify against the
  // ed25519 preimage.  This is the cross-language breakage that would occur if
  // an adapter used the wrong literal.
  assert.strictEqual(
    nodeVerify(null, correctPreimage, pubKey, sigOverWrong),
    false,
    'Signature over alg="EdDSA" preimage MUST NOT verify against alg="ed25519" preimage'
  );
});
