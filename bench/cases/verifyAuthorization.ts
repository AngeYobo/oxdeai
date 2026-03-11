import { createFixtureSet } from "../fixtures";
import { verifyAuthorization } from "@oxdeai/core";

export const name = "verifyAuthorization";

export function create(seed: number): () => unknown {
  const fixture = createFixtureSet(seed).complex;
  const auth = fixture.auth;
  const opts = {
    now: 1_700_000_000,
    expectedIssuer: "bench-issuer",
    expectedAudience: "bench-rp",
    expectedPolicyId: fixture.policy.id,
    consumedAuthIds: [] as string[],
    requireSignatureVerification: true,
    legacyHmacSecret: "bench-hmac-secret",
  };

  return () => {
    const out = verifyAuthorization(auth, opts);
    return out.status;
  };
}
