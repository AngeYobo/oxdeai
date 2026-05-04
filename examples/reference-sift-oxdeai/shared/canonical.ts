// SPDX-License-Identifier: Apache-2.0
/**
 * Sift-contract-compatible canonical JSON and cryptographic helpers.
 *
 * Inlined from @oxdeai/sift internals because siftCanonicalJsonBytes is not
 * part of the public API. Both the adapter (signing) and the PEP (verification)
 * must use this identical implementation to produce matching digests.
 *
 * Canonicalization contract:
 *   Equivalent to Python's:
 *     json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True)
 */

import { createHash, createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

type JsonPrimitive = string | number | boolean | null;
type JsonArray = JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonPrimitive | JsonArray | JsonObject;

// ─── Canonicalization ─────────────────────────────────────────────────────────

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

export function siftCanonicalJsonBytes(value: unknown): Uint8Array {
  const json = applyEnsureAscii(JSON.stringify(siftCanonicalize(value)));
  return new TextEncoder().encode(json);
}

export function siftCanonicalJsonHash(value: unknown): string {
  return createHash("sha256").update(siftCanonicalJsonBytes(value)).digest("hex");
}

// ─── base64url ────────────────────────────────────────────────────────────────

export function b64uEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function b64uDecode(s: string): Buffer {
  const normalized = s
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return Buffer.from(normalized, "base64url");
}

// ─── Ed25519 SPKI import ──────────────────────────────────────────────────────

// SEQUENCE { SEQUENCE { OID id-Ed25519 } BIT STRING { 0x00 [32 bytes] } }
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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

/** Extracts the raw 32-byte key material from a Node.js Ed25519 KeyObject. */
export function rawPublicKeyBytes(key: KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" }) as Buffer;
  return der.subarray(12); // strip the 12-byte SPKI prefix
}
