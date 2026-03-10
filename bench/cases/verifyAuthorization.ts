import { makeAuthorization } from "../fixtures";
import { verifyAuthorization } from "@oxdeai/core";

export const name = "verifyAuthorization";

export function create(): () => void {
  const auth = makeAuthorization();
  const opts = {
    now: Math.floor(Date.now() / 1000),
    expectedIssuer: "bench-issuer",
    expectedAudience: "bench-rp",
    expectedPolicyId: "a".repeat(64),
    consumedAuthIds: [] as string[]
  };

  return () => {
    verifyAuthorization(auth, opts);
  };
}
