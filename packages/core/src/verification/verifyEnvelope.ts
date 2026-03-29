import { decodeEnvelope } from "./envelope.js";
import { envelopeSigningPayload } from "./envelope.js";
import { verifySnapshot } from "./verifySnapshot.js";
import { verifyAuditEvents } from "./verifyAuditEvents.js";
import type { VerificationResult, VerificationViolation, VerifyEnvelopeOptions } from "./types.js";
import { findKeyInKeySets, keyIsActiveAt, SIGNING_DOMAINS, verifyEd25519 } from "../crypto/signatures.js";

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

/** @public */
export function verifyEnvelope(
  envelopeBytes: Uint8Array,
  opts?: VerifyEnvelopeOptions
): VerificationResult {
  let envelope;
  try {
    envelope = decodeEnvelope(envelopeBytes);
  } catch (error) {
    return {
      ok: false,
      status: "invalid",
      violations: [{ code: "ENVELOPE_MALFORMED", message: (error as Error).message || "envelope decode failed" }]
    };
  }

  const violations: VerificationViolation[] = [];
  const requireSig = opts?.requireSignatureVerification ?? false;
  const now = opts?.now ?? Math.floor(Date.now() / 1000);
  const trustedRaw = opts?.trustedKeySets;
  const trusted = trustedRaw ? (Array.isArray(trustedRaw) ? trustedRaw : [trustedRaw]) : [];

  if (opts?.mode === "strict" && trusted.length === 0) {
    return {
      ok: false,
      status: "invalid",
      violations: [{ code: "TRUSTED_KEYSETS_REQUIRED", message: "strict mode requires trustedKeySets to be provided" }]
    };
  }

  const hasSignature = typeof envelope.signature === "string" && envelope.signature.length > 0;

  if (opts?.expectedIssuer !== undefined && envelope.issuer !== opts.expectedIssuer) {
    violations.push({ code: "ENVELOPE_SIGNATURE_INVALID", message: "envelope issuer does not match expectedIssuer" });
  }
  if (requireSig && !hasSignature) {
    violations.push({ code: "ENVELOPE_SIGNATURE_MISSING", message: "signed envelope is required" });
  }
  if (hasSignature) {
    const signature = envelope.signature as string;
    if (envelope.alg !== "Ed25519") {
      violations.push({ code: "ENVELOPE_ALG_UNSUPPORTED", message: "unsupported envelope signature algorithm" });
    } else if (typeof envelope.kid !== "string" || envelope.kid.length === 0 || typeof envelope.issuer !== "string" || envelope.issuer.length === 0) {
      violations.push({ code: "ENVELOPE_SIGNATURE_INVALID", message: "signed envelope requires issuer, alg, kid, signature" });
    } else if (trusted.length === 0) {
      violations.push({ code: "ENVELOPE_TRUST_MISSING", message: "trustedKeySets required to verify signed envelope" });
    } else {
      const key = findKeyInKeySets(trusted, envelope.issuer, envelope.kid, "Ed25519");
      if (!key) {
        violations.push({ code: "ENVELOPE_KID_UNKNOWN", message: "envelope kid not found for issuer/alg" });
      } else if (!keyIsActiveAt(key, now)) {
        violations.push({ code: "ENVELOPE_KEY_INACTIVE", message: "envelope signing key is not active" });
      } else {
        const validSig = verifyEd25519(
          SIGNING_DOMAINS.ENVELOPE_V1,
          envelopeSigningPayload(envelope),
          signature,
          key.public_key
        );
        if (!validSig) {
          violations.push({ code: "ENVELOPE_SIGNATURE_INVALID", message: "envelope signature verification failed" });
        }
      }
    }
  }

  const snapshotResult = verifySnapshot(envelope.snapshot, {
    expectedPolicyId: opts?.expectedPolicyId
  });

  const auditResult = verifyAuditEvents(envelope.events, {
    expectedPolicyId: opts?.expectedPolicyId,
    mode: opts?.mode
  });

  violations.push(...snapshotResult.violations, ...auditResult.violations);

  const snapshotPolicyId = snapshotResult.policyId;
  const auditPolicyId = auditResult.policyId;

  if (!snapshotPolicyId || !auditPolicyId) {
    violations.push({ code: "POLICY_ID_MISSING", message: "snapshot and audit must both include policyId" });
  } else if (snapshotPolicyId !== auditPolicyId) {
    violations.push({ code: "POLICY_ID_MISMATCH", message: "snapshot policyId does not match audit policyId" });
  }

  const sorted = sortViolations(violations);
  const hasInvalid =
    snapshotResult.status === "invalid" ||
    auditResult.status === "invalid" ||
    sorted.some((v) => v.code !== "NO_STATE_ANCHOR");

  if (hasInvalid) {
    return {
      ok: false,
      status: "invalid",
      violations: sorted,
      policyId: snapshotPolicyId ?? auditPolicyId,
      stateHash: snapshotResult.stateHash,
      auditHeadHash: auditResult.auditHeadHash
    };
  }

  if (snapshotResult.status === "inconclusive" || auditResult.status === "inconclusive") {
    return {
      ok: false,
      status: "inconclusive",
      violations: sorted,
      policyId: snapshotPolicyId ?? auditPolicyId,
      stateHash: snapshotResult.stateHash,
      auditHeadHash: auditResult.auditHeadHash
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    policyId: snapshotPolicyId,
    stateHash: snapshotResult.stateHash,
    auditHeadHash: auditResult.auditHeadHash
  };
}
