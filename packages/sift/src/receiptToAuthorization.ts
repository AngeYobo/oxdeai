// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { SiftReceipt } from "./verifyReceipt.js";
import type { OxDeAIIntent } from "./normalizeIntent.js";
import type { NormalizedState } from "./state.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 30;

// ─── Public types ─────────────────────────────────────────────────────────────

export interface AuthorizationV1Payload {
  version: "AuthorizationV1";
  auth_id: string;
  issuer: string;
  audience: string;
  decision: "ALLOW";
  intent_hash: string;
  state_hash: string;
  policy_id: string;
  issued_at: number;
  expires_at: number;
  signature: {
    alg: "Ed25519";
    kid: string;
    sig: string;
  };
}

/**
 * The payload a signer should canonicalize and sign.
 * Identical to AuthorizationV1Payload except `signature.sig` is absent —
 * the sig field must not be present when producing the bytes to sign.
 */
export type SigningPayload = Omit<AuthorizationV1Payload, "signature"> & {
  signature: { alg: "Ed25519"; kid: string };
};

export interface ReceiptToAuthorizationInput {
  receipt: SiftReceipt;
  intent: OxDeAIIntent;
  state: NormalizedState;
  issuer: string;
  audience: string;
  keyId: string;
  ttlSeconds?: number;
  now?: Date;
}

export type ReceiptToAuthorizationErrorCode =
  | "INVALID_RECEIPT_DECISION"
  | "INVALID_BINDING_INPUT"
  | "INVALID_AUDIENCE"
  | "INVALID_ISSUER"
  | "INVALID_KEY_ID"
  | "INVALID_POLICY_ID"
  | "INVALID_TIMESTAMP"
  | "INVALID_TTL"
  | "INTENT_HASH_FAILED"
  | "STATE_HASH_FAILED"
  | "AUTHORIZATION_CONSTRUCTION_FAILED";

export type ReceiptToAuthorizationResult =
  | {
      ok: true;
      authorization: AuthorizationV1Payload;
      signingPayload: SigningPayload;
    }
  | {
      ok: false;
      code: ReceiptToAuthorizationErrorCode;
      message: string;
    };

// ─── Internal helpers ─────────────────────────────────────────────────────────

function fail(
  code: ReceiptToAuthorizationErrorCode,
  message: string
): ReceiptToAuthorizationResult {
  return { ok: false, code, message };
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

// ─── Local canonical JSON ─────────────────────────────────────────────────────

const textEncoder = new TextEncoder();

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [k: string]: JsonValue };

/**
 * Recursively produces a canonically-structured value: object keys are sorted
 * lexicographically, arrays preserve order, primitives pass through.
 *
 * Throws TypeError on bigint, symbol, function, undefined, or class instances
 * (Date, Map, Set, Buffer, Uint8Array, etc.). Inputs are expected to be
 * already-normalized plain data, but we guard defensively.
 *
 * Output objects use Object.create(null) so any key named "__proto__" is
 * stored as an own data property rather than invoking the setter.
 */
function canonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Non-finite number in payload: ${value}`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value) as unknown;
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(
        `Non-plain object in payload: ${Object.prototype.toString.call(value)}`
      );
    }
    const keys = Object.keys(value as object).sort();
    const out = Object.create(null) as { [k: string]: JsonValue };
    for (const k of keys) {
      out[k] = canonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  throw new TypeError(`Unsupported type in payload: ${typeof value}`);
}

/** SHA-256 lowercase hex of the canonical JSON UTF-8 encoding of `value`. */
function canonicalJsonHash(value: unknown): string {
  const json = JSON.stringify(canonicalize(value));
  return createHash("sha256").update(textEncoder.encode(json)).digest("hex");
}

// ─── Main exported function ───────────────────────────────────────────────────

/**
 * Converts a locally verified Sift receipt, a normalized intent, and a
 * normalized state snapshot into an unsigned AuthorizationV1 payload and
 * the corresponding signing payload ready for Ed25519 signing.
 *
 * Binding invariants enforced here:
 *   auth_id   ← receipt.nonce          (explicit replay identity)
 *   policy_id ← receipt.policy_matched (explicit policy binding)
 *   intent_hash ← SHA-256(canonical intent)
 *   state_hash  ← SHA-256(canonical state)
 *
 * The returned `authorization.signature.sig` is an empty string placeholder.
 * Signing must happen outside this file.
 *
 * Fails closed: any ambiguity or missing binding returns `{ ok: false }`.
 */
export function receiptToAuthorization(
  input: ReceiptToAuthorizationInput
): ReceiptToAuthorizationResult {
  try {
    const { receipt, intent, state, issuer, audience, keyId } = input;

    // ── 1. Receipt decision ────────────────────────────────────────────────
    // Only ALLOW receipts may produce authorization payloads.
    if (receipt.decision !== "ALLOW") {
      return fail(
        "INVALID_RECEIPT_DECISION",
        `Receipt decision must be ALLOW, got: ${receipt.decision}`
      );
    }

    // ── 2. Binding string preconditions ────────────────────────────────────
    if (!isNonEmptyString(issuer)) {
      return fail("INVALID_ISSUER", "issuer must be a non-empty string");
    }
    if (!isNonEmptyString(audience)) {
      return fail("INVALID_AUDIENCE", "audience must be a non-empty string");
    }
    if (!isNonEmptyString(keyId)) {
      return fail("INVALID_KEY_ID", "keyId must be a non-empty string");
    }

    // ── 3. Policy binding ─────────────────────────────────────────────────
    // policy_id maps explicitly from receipt.policy_matched.
    if (!isNonEmptyString(receipt.policy_matched)) {
      return fail(
        "INVALID_POLICY_ID",
        "receipt.policy_matched must be a non-empty string"
      );
    }

    // ── 4. Binding object preconditions ───────────────────────────────────
    // intent and state are typed as their normalized forms, but guard
    // defensively against runtime bypass via `as any`.
    if (intent === null || intent === undefined || typeof intent !== "object") {
      return fail("INVALID_BINDING_INPUT", "intent must be a non-null object");
    }
    if (state === null || state === undefined || typeof state !== "object") {
      return fail("INVALID_BINDING_INPUT", "state must be a non-null object");
    }

    // ── 5. TTL validation ─────────────────────────────────────────────────
    const ttlSeconds = input.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
      return fail(
        "INVALID_TTL",
        "ttlSeconds must be a positive safe integer"
      );
    }

    // ── 6. Time binding ───────────────────────────────────────────────────
    // Capture time exactly once; derive issued_at and expires_at from it.
    const nowDate = input.now ?? new Date();
    // instanceof guard defends against non-Date values passed via `as any`
    const nowMs = nowDate instanceof Date ? nowDate.getTime() : NaN;
    if (!Number.isFinite(nowMs)) {
      return fail("INVALID_TIMESTAMP", "now must be a valid Date");
    }
    const issuedAt = Math.floor(nowMs / 1000);
    const expiresAt = issuedAt + ttlSeconds;

    // ── 7. Intent hash ────────────────────────────────────────────────────
    let intentHash: string;
    try {
      intentHash = canonicalJsonHash(intent);
    } catch (e) {
      return fail(
        "INTENT_HASH_FAILED",
        `Failed to canonicalize intent: ${e instanceof Error ? e.message : String(e)}`
      );
    }

    // ── 8. State hash ─────────────────────────────────────────────────────
    let stateHash: string;
    try {
      stateHash = canonicalJsonHash(state);
    } catch (e) {
      return fail(
        "STATE_HASH_FAILED",
        `Failed to canonicalize state: ${e instanceof Error ? e.message : String(e)}`
      );
    }

    // ── 9. Construct authorization payload ────────────────────────────────
    // Every field is explicitly bound — no computed defaults that weaken
    // audience, issuer, or policy binding.
    const authorization: AuthorizationV1Payload = {
      version: "AuthorizationV1",
      auth_id: receipt.nonce,          // replay identity ← receipt.nonce
      issuer,
      audience,
      decision: "ALLOW",
      intent_hash: intentHash,
      state_hash: stateHash,
      policy_id: receipt.policy_matched, // policy binding ← receipt.policy_matched
      issued_at: issuedAt,
      expires_at: expiresAt,
      signature: {
        alg: "Ed25519",
        kid: keyId,
        sig: "",                       // placeholder — sig is empty until signed
      },
    };

    // ── 10. Construct signing payload ─────────────────────────────────────
    // Identical to authorization except signature.sig is absent.
    // A signer MUST canonicalize this object and produce the Ed25519 sig.
    const signingPayload: SigningPayload = {
      version: authorization.version,
      auth_id: authorization.auth_id,
      issuer: authorization.issuer,
      audience: authorization.audience,
      decision: authorization.decision,
      intent_hash: authorization.intent_hash,
      state_hash: authorization.state_hash,
      policy_id: authorization.policy_id,
      issued_at: authorization.issued_at,
      expires_at: authorization.expires_at,
      signature: {
        alg: "Ed25519",
        kid: keyId,
        // sig intentionally absent
      },
    };

    return { ok: true, authorization, signingPayload };
  } catch (e) {
    return fail(
      "AUTHORIZATION_CONSTRUCTION_FAILED",
      `Unexpected error during authorization construction: ${e instanceof Error ? e.message : String(e)}`
    );
  }
}
