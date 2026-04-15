// SPDX-License-Identifier: Apache-2.0
/**
 * Sift-contract-compatible canonicalization and cryptographic helpers.
 *
 * These functions implement the exact wire format required by the Sift staging
 * verifier contract.  They are used only at Sift-facing boundaries within this
 * package — do NOT use them for unrelated OxDeAI-internal artifact semantics.
 *
 * Canonicalization contract:
 *   Equivalent to Python's:
 *     json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=True)
 *
 * Signature encoding: base64url, no padding (RFC 4648 §5).
 * Public key format:  raw 32-byte Ed25519 key material (JWKS `x` field).
 */

import { createHash, createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

type JsonPrimitive = string | number | boolean | null;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// ─── Canonicalization ─────────────────────────────────────────────────────────

/**
 * Recursively produces a canonically-structured value: object keys sorted
 * lexicographically, arrays preserved, primitives passed through.
 *
 * Output objects use Object.create(null) so any key named "__proto__" is stored
 * as an own data property rather than invoking the setter.
 *
 * Throws TypeError on bigint, symbol, function, undefined, or class instances
 * (Date, Map, Set, Buffer, Uint8Array, etc.).  Inputs are expected to be
 * already-normalized plain data, but guarded defensively.
 */
export function siftCanonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Non-finite number in Sift payload: ${value}`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return (value as unknown[]).map(siftCanonicalize);
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value) as unknown;
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(
        `Non-plain object in Sift payload: ${Object.prototype.toString.call(value)}`
      );
    }
    const keys = Object.keys(value as object).sort();
    const out = Object.create(null) as JsonObject;
    for (const k of keys) {
      out[k] = siftCanonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  throw new TypeError(`Unsupported type in Sift payload: ${typeof value}`);
}

/**
 * Applies Python ensure_ascii=True semantics to a JSON string.
 *
 * Every UTF-16 code unit outside 0x00–0x7F is escaped as \uXXXX (lowercase
 * four-digit hex).  For supplementary characters (U+10000+), JavaScript
 * represents them as two surrogate code units (U+D800–U+DFFF); each surrogate
 * is individually escaped — matching Python's ensure_ascii behavior exactly.
 *
 * This is called AFTER JSON.stringify so that JSON's own control-character
 * escaping (U+0000–U+001F) is already in place and is not double-escaped.
 */
function applyEnsureAscii(json: string): string {
  let out = "";
  for (let i = 0; i < json.length; i++) {
    const code = json.charCodeAt(i);
    if (code > 0x7f) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += json[i];
    }
  }
  return out;
}

/**
 * Returns the UTF-8 bytes of the Sift-canonical JSON serialization of `value`.
 *
 * Equivalent to Python:
 *   json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True)
 *   .encode("utf-8")
 *
 * Because ensure_ascii=True produces an ASCII-only string, every byte of the
 * output is exactly the Unicode code point of the corresponding character.
 */
export function siftCanonicalJsonBytes(value: unknown): Uint8Array {
  const json = applyEnsureAscii(JSON.stringify(siftCanonicalize(value)));
  return new TextEncoder().encode(json);
}

/** SHA-256 lowercase hex of the Sift-canonical JSON UTF-8 encoding of `value`. */
export function siftCanonicalJsonHash(value: unknown): string {
  return createHash("sha256").update(siftCanonicalJsonBytes(value)).digest("hex");
}

// ─── base64url helpers ─────────────────────────────────────────────────────────

/** Encodes a Buffer to base64url without padding (RFC 4648 §5). */
export function b64uEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Decodes a base64url-no-padding (or standard base64) string to a Buffer.
 *
 * Normalizes standard base64 input (`+` → `-`, `/` → `_`) before decoding as
 * base64url.  This is safe because base64 index 62 is `+` in standard and `-`
 * in URL-safe form, and index 63 is `/`/`_` — both representations encode the
 * same bit patterns, so normalization is bijective over the 6-bit alphabet.
 *
 * Consequence: this function accepts both the Sift-native base64url signatures
 * sent by the production Sift service, AND standard-base64 signatures produced
 * by test helpers that call `.toString("base64")`.
 */
export function b64uDecode(s: string): Buffer {
  const normalized = s
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return Buffer.from(normalized, "base64url");
}

// ─── Raw Ed25519 public key import ────────────────────────────────────────────

// SPKI DER wrapper for an Ed25519 public key.
//
//   SEQUENCE (42 bytes total)
//     SEQUENCE (5 bytes)
//       OID 1.3.101.112  (id-Ed25519)
//     BIT STRING (33 bytes)
//       0x00             (0 unused bits)
//       [32 bytes raw public key]
//
// Prefix hex: 302a300506032b6570032100  (12 bytes)

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Creates a Node.js KeyObject from a raw 32-byte Ed25519 public key.
 *
 * `rawKey` is either:
 *   - a `Uint8Array` of exactly 32 bytes, or
 *   - a base64url-no-padding string (the `x` field from a JWKS entry).
 *
 * Throws a TypeError if the decoded key material is not exactly 32 bytes.
 */
export function publicKeyFromRaw(rawKey: string | Uint8Array): KeyObject {
  const keyBytes =
    typeof rawKey === "string" ? b64uDecode(rawKey) : Buffer.from(rawKey);
  if (keyBytes.length !== 32) {
    throw new TypeError(
      `Ed25519 public key must be exactly 32 bytes, got ${keyBytes.length}`
    );
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, keyBytes]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}
