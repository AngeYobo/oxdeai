import { makeEnvelopeData } from "../fixtures";
import { verifyEnvelope } from "@oxdeai/core";

export const name = "verifyEnvelope";

export function create(strict = false): () => void {
  const envelope = makeEnvelopeData();

  return () => {
    verifyEnvelope(envelope.bytes, {
      mode: strict ? "strict" : "best-effort",
      expectedPolicyId: envelope.policyId,
      trustedKeySets: envelope.trustedKeySet,
      requireSignatureVerification: true,
      now: Math.floor(Date.now() / 1000)
    });
  };
}
