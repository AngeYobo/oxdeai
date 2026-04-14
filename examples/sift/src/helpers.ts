// SPDX-License-Identifier: Apache-2.0
/**
 * Self-contained helpers for the Sift integration demo.
 *
 * These implementations are intentionally explicit about every preimage so
 * the demo is pedagogically clear.  No internals from @oxdeai/sift are
 * imported — only its public types.
 *
 * Preimage conventions that must match packages/sift/src/verifyReceipt.ts:
 *
 *   receipt_hash preimage:  canonical( receipt  MINUS  signature  AND  receipt_hash )
 *   receipt signature:      canonical( receipt  MINUS  signature,  WITH receipt_hash )
 *
 * Preimage convention that must match packages/sift/src/receiptToAuthorization.ts:
 *
 *   authorization signature:  canonical( signingPayload )
 *                             where signingPayload = authorization WITHOUT signature.sig
 */

import {
  generateKeyPairSync,
  sign as nodeCryptoSign,
  verify as nodeCryptoVerify,
  createHash,
  randomUUID,
} from "node:crypto";
import type {
  SiftDecision,
  OxDeAIIntent,
  NormalizedState,
  AuthorizationV1Payload,
  SigningPayload,
} from "@oxdeai/sift";

// ─── Canonical JSON ──────────────────────────────────────────────────────────
// Mirrors the canonicalize + canonicalJsonHash logic inside the sift package.
// Keys sorted lexicographically at every object level; arrays preserve order.

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

function canonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite number: ${value}`);
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

/** UTF-8 bytes of the sorted-key minified JSON encoding of `value`. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf-8");
}

/** SHA-256 lowercase hex of `data`. */
export function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 lowercase hex of canonical JSON of `value`. */
export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalBytes(value));
}

// ─── Ed25519 key management ──────────────────────────────────────────────────

export interface DemoKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function makeKeyPair(): DemoKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/**
 * Signs canonical JSON bytes of `value` with the given Ed25519 private key.
 * Returns the signature as base64.
 */
export function signCanonical(value: unknown, privateKeyPem: string): string {
  return nodeCryptoSign(null, canonicalBytes(value), privateKeyPem).toString("base64");
}

/**
 * Verifies an Ed25519 base64 signature over canonical JSON bytes of `value`.
 * Returns false on any error rather than throwing.
 */
export function verifyCanonical(
  value: unknown,
  sigBase64: string,
  publicKeyPem: string
): boolean {
  try {
    return nodeCryptoVerify(
      null,
      canonicalBytes(value),
      publicKeyPem,
      Buffer.from(sigBase64, "base64")
    );
  } catch {
    return false;
  }
}

// ─── Mock Sift receipt builder ───────────────────────────────────────────────
// Produces a structurally valid receipt with a correctly-computed receipt_hash
// and a real Ed25519 signature.  This simulates a receipt that would arrive
// from the Sift governance service.
//
// Preimage order (critical — must match verifyReceipt.ts computeReceiptHash):
//   ① Build body (no receipt_hash, no signature)
//   ② receipt_hash = sha256( canonical( ① ) )
//   ③ signed payload = ① + receipt_hash   (signature field absent)
//   ④ signature = sign( canonical( ③ ) )

export interface BuildReceiptOptions {
  decision: SiftDecision;
  keypair: DemoKeyPair;
  nonce?: string;
  tool?: string;
  action?: string;
  now?: Date;
}

export function buildMockReceipt(opts: BuildReceiptOptions): Record<string, unknown> {
  const {
    decision,
    keypair,
    nonce = randomUUID(),
    tool = "query_database",
    action = "call_tool",
    now = new Date(),
  } = opts;

  // ① Receipt body — no receipt_hash, no signature.
  const base = {
    receipt_version: "1.0",
    tenant_id: "demo-tenant",
    agent_id: "demo-agent",
    action,
    tool,
    decision,
    risk_tier: 1,
    timestamp: now.toISOString(),
    nonce,
    policy_matched: "policy-tools-v1",
  };

  // ② receipt_hash = SHA-256( canonical( body ) )
  const receipt_hash = canonicalHash(base);

  // ③ Signed payload = body + receipt_hash  (signature still absent)
  const withHash = { ...base, receipt_hash };

  // ④ signature = sign( canonical( ③ ) )
  const signature = signCanonical(withHash, keypair.privateKeyPem);

  return { ...withHash, signature };
}

// ─── Authorization signing ───────────────────────────────────────────────────
// Fills the `sig` placeholder in authorization.signature by signing the
// signingPayload returned by receiptToAuthorization.
//
// The signingPayload is already the correct preimage — it is the full
// authorization with signature.sig intentionally absent.

export function signAuthorization(
  authorization: AuthorizationV1Payload,
  signingPayload: SigningPayload,
  issuerPrivateKeyPem: string
): AuthorizationV1Payload {
  const sig = signCanonical(signingPayload, issuerPrivateKeyPem);
  return { ...authorization, signature: { ...authorization.signature, sig } };
}

// ─── PEP simulation ──────────────────────────────────────────────────────────
// A minimal local Policy Enforcement Point.
//
// The Sift receipt is NOT the execution gate — it is upstream governance input.
// The PEP is the execution boundary.  A signed AuthorizationV1 artifact,
// verified here, is required before any execution can proceed.
//
// Checks performed in order:
//   1. Audience exact match
//   2. Expiry (expires_at > floor(now / 1000))
//   3. Ed25519 signature on reconstructed signingPayload
//   4. intent_hash matches the provided intent
//   5. state_hash matches the provided state
//   6. Replay: auth_id must not have been seen before

export type PepResult =
  | { ok: true; decision: "ALLOW"; executed: true; auth_id: string }
  | { ok: false; decision: "DENY"; executed: false; reason: string };

// In-memory replay store — scoped to this demo process.
const pepReplayStore = new Set<string>();

export interface PepVerifyInput {
  authorization: AuthorizationV1Payload;
  intent: OxDeAIIntent;
  state: NormalizedState;
  audience: string;
  issuerPublicKeyPem: string;
  now: Date;
}

export function pepVerify(input: PepVerifyInput): PepResult {
  const { authorization, intent, state, audience, issuerPublicKeyPem, now } = input;

  // 1. Audience
  if (authorization.audience !== audience) {
    return { ok: false, decision: "DENY", executed: false, reason: "AUDIENCE_MISMATCH" };
  }

  // 2. Expiry
  const nowSec = Math.floor(now.getTime() / 1000);
  if (authorization.expires_at <= nowSec) {
    return { ok: false, decision: "DENY", executed: false, reason: "EXPIRED" };
  }

  // 3. Signature — reconstruct signing payload (authorization without signature.sig)
  //    Must produce the same canonical bytes that were signed by the issuer.
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
    signature: { alg: authorization.signature.alg, kid: authorization.signature.kid },
  };
  if (!verifyCanonical(signingPayload, authorization.signature.sig, issuerPublicKeyPem)) {
    return { ok: false, decision: "DENY", executed: false, reason: "INVALID_SIGNATURE" };
  }

  // 4. Intent hash — recompute from the provided intent and compare.
  if (authorization.intent_hash !== canonicalHash(intent)) {
    return { ok: false, decision: "DENY", executed: false, reason: "INTENT_HASH_MISMATCH" };
  }

  // 5. State hash — recompute from the provided state and compare.
  if (authorization.state_hash !== canonicalHash(state)) {
    return { ok: false, decision: "DENY", executed: false, reason: "STATE_HASH_MISMATCH" };
  }

  // 6. Replay — the auth_id must be consumed exactly once.
  if (pepReplayStore.has(authorization.auth_id)) {
    return { ok: false, decision: "DENY", executed: false, reason: "REPLAY" };
  }
  pepReplayStore.add(authorization.auth_id);

  return { ok: true, decision: "ALLOW", executed: true, auth_id: authorization.auth_id };
}
