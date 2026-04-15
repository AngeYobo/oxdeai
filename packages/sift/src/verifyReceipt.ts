// SPDX-License-Identifier: Apache-2.0
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import {
  siftCanonicalJsonBytes,
  b64uDecode,
  publicKeyFromRaw,
} from "./siftCanonical.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const SUPPORTED_RECEIPT_VERSIONS: readonly string[] = ["1.0"];
const DEFAULT_MAX_AGE_MS = 30_000;
/** Tolerate receipts issued slightly in the future due to clock skew. */
const MAX_FUTURE_SKEW_MS = 5_000;

// ─── Public types ─────────────────────────────────────────────────────────────

export type SiftDecision = "ALLOW" | "DENY";

export interface SiftReceipt {
  receipt_version: string;
  tenant_id: string;
  agent_id: string;
  action: string;
  tool: string;
  decision: SiftDecision;
  risk_tier: number;
  timestamp: string;
  nonce: string;
  policy_matched: string;
  receipt_hash: string;
  signature: string;
}

export interface VerifyReceiptOptions {
  /**
   * Raw 32-byte Ed25519 public key — either as a Uint8Array or as a
   * base64url-no-padding string (the `x` field from a JWKS entry).
   *
   * This is the primary Sift-contract-native verification input.  The key is
   * imported via SPKI DER wrapping; no PEM or JWK structure is required from
   * the caller.
   */
  publicKeyRaw?: string | Uint8Array;
  /**
   * @deprecated Prefer `publicKeyRaw`.
   * PEM-encoded SPKI Ed25519 public key.  Accepted for backward compatibility
   * with tooling that already holds PEM material.  `publicKeyRaw` takes
   * precedence when both are provided.
   */
  publicKeyPem?: string;
  now?: Date;
  maxAgeMs?: number;
  /** Defaults to true. Set to false to allow DENY receipts through structural checks. */
  requireAllowDecision?: boolean;
}

export type VerifyReceiptErrorCode =
  | "MALFORMED_RECEIPT"
  | "UNSUPPORTED_RECEIPT_VERSION"
  | "INVALID_DECISION"
  | "DENY_DECISION"
  | "INVALID_TIMESTAMP"
  | "STALE_RECEIPT"
  | "INVALID_RECEIPT_HASH"
  | "INVALID_SIGNATURE"
  | "UNSUPPORTED_PUBLIC_KEY"
  | "VERIFICATION_ERROR";

export type VerifyReceiptResult =
  | {
      ok: true;
      receipt: SiftReceipt;
      verifiedAt: string;
      receiptHash: string;
    }
  | {
      ok: false;
      code: VerifyReceiptErrorCode;
      message: string;
    };

// ─── Internal helpers ─────────────────────────────────────────────────────────

function fail(code: VerifyReceiptErrorCode, message: string): VerifyReceiptResult {
  return { ok: false, code, message };
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isFiniteNonNegativeInteger(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    Number.isInteger(v) &&
    v >= 0
  );
}

// ─── Structural validation ────────────────────────────────────────────────────

type ParseReceiptError = { _tag: "error"; result: VerifyReceiptResult };
type ParseReceiptOk = { _tag: "ok"; receipt: SiftReceipt };

function parseReceipt(raw: unknown): ParseReceiptOk | ParseReceiptError {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return {
      _tag: "error",
      result: fail("MALFORMED_RECEIPT", "Receipt must be a non-null object"),
    };
  }

  const r = raw as Record<string, unknown>;

  const requiredStringFields = [
    "receipt_version",
    "tenant_id",
    "agent_id",
    "action",
    "tool",
    "timestamp",
    "nonce",
    "policy_matched",
    "receipt_hash",
    "signature",
  ] as const;

  for (const field of requiredStringFields) {
    if (!isNonEmptyString(r[field])) {
      return {
        _tag: "error",
        result: fail("MALFORMED_RECEIPT", `Field '${field}' must be a non-empty string`),
      };
    }
  }

  const decision = r["decision"];
  if (decision !== "ALLOW" && decision !== "DENY") {
    return {
      _tag: "error",
      result: fail(
        "INVALID_DECISION",
        `Field 'decision' must be "ALLOW" or "DENY", got: ${String(decision)}`
      ),
    };
  }

  if (!isFiniteNonNegativeInteger(r["risk_tier"])) {
    return {
      _tag: "error",
      result: fail(
        "MALFORMED_RECEIPT",
        "Field 'risk_tier' must be a finite non-negative integer"
      ),
    };
  }

  return {
    _tag: "ok",
    receipt: {
      receipt_version: r["receipt_version"] as string,
      tenant_id: r["tenant_id"] as string,
      agent_id: r["agent_id"] as string,
      action: r["action"] as string,
      tool: r["tool"] as string,
      decision: decision as SiftDecision,
      risk_tier: r["risk_tier"] as number,
      timestamp: r["timestamp"] as string,
      nonce: r["nonce"] as string,
      policy_matched: r["policy_matched"] as string,
      receipt_hash: r["receipt_hash"] as string,
      signature: r["signature"] as string,
    },
  };
}

// ─── Receipt hash ─────────────────────────────────────────────────────────────

/** Strips the optional "sha256:" prefix and lowercases. */
function normalizeHashHex(raw: string): string {
  const lower = raw.toLowerCase();
  return lower.startsWith("sha256:") ? lower.slice(7) : lower;
}

/**
 * Recomputes the SHA-256 hash of the receipt, excluding `signature` and
 * `receipt_hash` — the two fields intentionally outside the hash scope.
 *
 * Uses Sift-canonical JSON (ensure_ascii=True) to match the Sift wire format.
 */
function computeReceiptHash(receipt: SiftReceipt): string {
  const { signature: _sig, receipt_hash: _hash, ...payload } = receipt;
  return createHash("sha256").update(siftCanonicalJsonBytes(payload)).digest("hex");
}

// ─── Main exported function ───────────────────────────────────────────────────

/**
 * Verifies a Sift governance receipt locally.
 *
 * Verification order (integrity before semantics):
 *   1. Structural validation  — field presence, types
 *   2. Version check          — supported receipt_version
 *   3. Receipt hash           — SHA-256 of canonical JSON (ensure_ascii) of
 *                               receipt minus signature and receipt_hash
 *   4. Ed25519 signature      — over canonical JSON of receipt minus signature
 *                               (receipt_hash IS in the signed scope)
 *   5. Decision               — ALLOW enforcement (if requireAllowDecision)
 *   6. Freshness              — timestamp age and future-skew limits
 *
 * Fails closed: any ambiguity or error returns `{ ok: false }`.
 * No network calls are made.
 */
export function verifyReceipt(
  receipt: unknown,
  options: VerifyReceiptOptions
): VerifyReceiptResult {
  try {
    // ── 1. Structural validation ──────────────────────────────────────────────
    const parsed = parseReceipt(receipt);
    if (parsed._tag === "error") return parsed.result;
    const r = parsed.receipt;

    // ── 2. Supported version ──────────────────────────────────────────────────
    if (!SUPPORTED_RECEIPT_VERSIONS.includes(r.receipt_version)) {
      return fail(
        "UNSUPPORTED_RECEIPT_VERSION",
        `Receipt version '${r.receipt_version}' is not supported`
      );
    }

    // ── 3. Receipt hash integrity ─────────────────────────────────────────────
    // Integrity must be established before any semantic interpretation.
    const recomputedHash = computeReceiptHash(r);
    const claimedHash = normalizeHashHex(r.receipt_hash);

    if (claimedHash !== recomputedHash) {
      return fail(
        "INVALID_RECEIPT_HASH",
        "Receipt hash does not match recomputed canonical hash"
      );
    }

    // ── 4. Ed25519 signature verification ─────────────────────────────────────
    // Signed scope: the full receipt minus `signature`; `receipt_hash` IS
    // included because it passed integrity validation above.
    const { signature: signatureStr, ...signedPayload } = r;

    // Key resolution: publicKeyRaw (Sift-native) takes precedence over the
    // deprecated publicKeyPem path.
    let publicKey: ReturnType<typeof createPublicKey>;
    if (options.publicKeyRaw !== undefined) {
      try {
        publicKey = publicKeyFromRaw(options.publicKeyRaw);
      } catch {
        return fail(
          "UNSUPPORTED_PUBLIC_KEY",
          "Failed to import Ed25519 public key from raw bytes"
        );
      }
    } else if (options.publicKeyPem !== undefined) {
      try {
        publicKey = createPublicKey(options.publicKeyPem);
      } catch {
        return fail("UNSUPPORTED_PUBLIC_KEY", "Failed to parse Ed25519 public key from PEM");
      }
    } else {
      return fail(
        "UNSUPPORTED_PUBLIC_KEY",
        "Either publicKeyRaw or publicKeyPem must be provided"
      );
    }

    let signatureValid: boolean;
    try {
      // Sift-canonical bytes (ensure_ascii=True) for the signed scope.
      const sigInput = siftCanonicalJsonBytes(signedPayload);
      // b64uDecode accepts both base64url (Sift-native) and standard base64
      // (backward-compat) — see siftCanonical.ts for the normalization rationale.
      const sigBytes = b64uDecode(signatureStr);
      // null algorithm is the correct form for Ed25519 in Node.js crypto.
      signatureValid = verifySignature(null, sigInput, publicKey, sigBytes);
    } catch {
      return fail("VERIFICATION_ERROR", "An error occurred during signature verification");
    }

    if (!signatureValid) {
      return fail("INVALID_SIGNATURE", "Ed25519 signature verification failed");
    }

    // ── 5. Decision enforcement ───────────────────────────────────────────────
    // Semantic check only after integrity and authenticity are established.
    const requireAllow = options.requireAllowDecision !== false;
    if (requireAllow && r.decision !== "ALLOW") {
      return fail("DENY_DECISION", "Receipt decision is DENY");
    }

    // ── 6. Freshness validation ───────────────────────────────────────────────
    const nowMs = (options.now ?? new Date()).getTime();
    const maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;

    const receiptMs = Date.parse(r.timestamp);
    if (!Number.isFinite(receiptMs)) {
      return fail("INVALID_TIMESTAMP", `Cannot parse timestamp as ISO-8601: ${r.timestamp}`);
    }

    const ageMs = nowMs - receiptMs;

    if (ageMs < -MAX_FUTURE_SKEW_MS) {
      return fail(
        "INVALID_TIMESTAMP",
        `Receipt timestamp is too far in the future (delta: ${Math.abs(ageMs)}ms, max skew: ${MAX_FUTURE_SKEW_MS}ms)`
      );
    }

    if (ageMs > maxAgeMs) {
      return fail("STALE_RECEIPT", `Receipt is stale (age: ${ageMs}ms, maxAgeMs: ${maxAgeMs})`);
    }

    // ── 7. Success ────────────────────────────────────────────────────────────
    return {
      ok: true,
      receipt: r,
      verifiedAt: new Date(nowMs).toISOString(),
      receiptHash: recomputedHash,
    };
  } catch (err) {
    return fail(
      "VERIFICATION_ERROR",
      `Unexpected error during verification: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}
