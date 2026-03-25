import { generateKeyPairSync } from "node:crypto";
import { createDelegation, verifyDelegation, verifyDelegationChain } from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { createFixtureSet } from "../fixtures.js";

export const name = "verifyDelegation";

export function create(seed: number): () => unknown {
  const fixture = createFixtureSet(seed).complex;

  const { privateKey: privateKeyPem, publicKey: publicKeyPem } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });

  const kid = "bench-delegation-key-2026";
  const issuer = "bench-issuer";

  // Extract AuthorizationV1 fields from the combined Authorization fixture.
  const parent: AuthorizationV1 = {
    auth_id:    fixture.auth.auth_id,
    issuer:     fixture.auth.issuer,
    audience:   fixture.auth.audience,
    intent_hash: fixture.auth.intent_hash,
    state_hash: fixture.auth.state_hash,
    policy_id:  fixture.auth.policy_id,
    decision:   fixture.auth.decision,
    issued_at:  fixture.auth.issued_at,
    expiry:     fixture.auth.expiry,
    alg:        fixture.auth.alg,
    kid:        fixture.auth.kid,
    signature:  fixture.auth.signature,
  };

  const delegation = createDelegation(
    parent,
    {
      delegatee: "bench-sub-agent",
      scope: { tools: ["settle_invoice"], max_amount: 500n },
      expiry: 1_700_000_000 + 120,
      kid,
      issuer,
      delegationId: "bench-delegation-id-001",
      issuedAt: 1_700_000_000,
    },
    privateKeyPem
  );

  const trustedKeySets: KeySet = {
    issuer,
    version: "1",
    keys: [{ kid, alg: "Ed25519", public_key: publicKeyPem }],
  };

  const opts = {
    now: 1_700_000_000,
    trustedKeySets,
    requireSignatureVerification: true,
    expectedPolicyId: fixture.policy.id,
    expectedDelegatee: "bench-sub-agent",
    parentScope: { tools: ["settle_invoice", "pay_vendor"], max_amount: 1000n },
  };

  const chainOpts = {
    now: 1_700_000_000,
    trustedKeySets,
    requireSignatureVerification: true,
    expectedDelegatee: "bench-sub-agent",
  };

  return () => {
    const r = verifyDelegation(delegation, opts);
    return r.status;
  };
}

export function createChain(seed: number): () => unknown {
  const fixture = createFixtureSet(seed).complex;

  const { privateKey: privateKeyPem, publicKey: publicKeyPem } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });

  const kid = "bench-chain-key-2026";
  const issuer = "bench-issuer";

  const parent: AuthorizationV1 = {
    auth_id:    fixture.auth.auth_id,
    issuer:     fixture.auth.issuer,
    audience:   fixture.auth.audience,
    intent_hash: fixture.auth.intent_hash,
    state_hash: fixture.auth.state_hash,
    policy_id:  fixture.auth.policy_id,
    decision:   fixture.auth.decision,
    issued_at:  fixture.auth.issued_at,
    expiry:     fixture.auth.expiry,
    alg:        fixture.auth.alg,
    kid:        fixture.auth.kid,
    signature:  fixture.auth.signature,
  };

  const delegation = createDelegation(
    parent,
    {
      delegatee: "bench-sub-agent",
      scope: { tools: ["settle_invoice"], max_amount: 500n },
      expiry: 1_700_000_000 + 120,
      kid,
      issuer,
      delegationId: "bench-chain-delegation-001",
      issuedAt: 1_700_000_000,
    },
    privateKeyPem
  );

  const trustedKeySets: KeySet = {
    issuer,
    version: "1",
    keys: [{ kid, alg: "Ed25519", public_key: publicKeyPem }],
  };

  return () => {
    const r = verifyDelegationChain(delegation, parent, {
      now: 1_700_000_000,
      trustedKeySets,
      requireSignatureVerification: true,
      expectedDelegatee: "bench-sub-agent",
    });
    return r.status;
  };
}
