// Demo-only Ed25519 issuer fixture for the non-bypassable gateway example.
// The private key is intentionally local to this example.

import {
  sha256HexFromJson,
  signAuthorizationEd25519,
} from "../../packages/core/dist/index.js";

export const DEMO_ISSUER = "demo-issuer";
export const DEMO_KID = "demo-ed25519-k1";
export const DEMO_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApdJ5V8bSa4FHBIMOKrr0hO7k7d1KuGg0/0hy+8Qykps=
-----END PUBLIC KEY-----
`;
export const DEMO_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICv0KhnKaIEym0X8eWZhqfELT2oq9TYbQG6/m3l0Q+GO
-----END PRIVATE KEY-----
`;

export const DEMO_KEYSET = {
  issuer: DEMO_ISSUER,
  version: "v1",
  keys: [{ kid: DEMO_KID, alg: "Ed25519", public_key: DEMO_PUBLIC_KEY_PEM }],
};

export { sha256HexFromJson as hashAction };

export function makeAuthorization({
  action,
  authId,
  audience = "pep-gateway.local",
  decision = "ALLOW",
  intentHash,
  expiresInSeconds = 3600,
  issuedAt = Math.floor(Date.now() / 1000),
} = {}) {
  return signAuthorizationEd25519(
    {
      auth_id: authId ?? `auth_${Date.now()}`,
      issuer: DEMO_ISSUER,
      audience,
      decision,
      intent_hash: intentHash ?? sha256HexFromJson(action),
      state_hash: sha256HexFromJson({ demo_state: "ok" }),
      policy_id: "demo-policy-v1",
      issued_at: issuedAt,
      expiry: issuedAt + expiresInSeconds,
      kid: DEMO_KID,
      nonce: "demo-nonce",
      capability: "execute",
    },
    DEMO_PRIVATE_KEY_PEM
  );
}
