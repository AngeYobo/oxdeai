// SPDX-License-Identifier: Apache-2.0
/**
 * Delegation test matrix — packages/core
 *
 * Covers the 9 required cases for DelegationV1 authorization.
 * Cases 7 (guard success) and 8 (guard failure) are covered in
 * packages/guard/src/test/guard.delegation.matrix.test.ts.
 *
 * All timestamps are fixed integers — no Date.now() calls in test logic.
 * Key material is generated once per file load (deterministic within a run).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { canonicalJson } from "../crypto/hashes.js";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import { createDelegation } from "../delegation/createDelegation.js";
import {
  verifyDelegation,
  verifyDelegationChain,
  delegationParentHash,
  delegationSigningPayload,
} from "../verification/verifyDelegation.js";
import type { KeySet } from "../types/keyset.js";
import type { AuthorizationV1 } from "../types/authorization.js";

// ── Fixed key material ────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

// Delegation keyset: issuer = delegating principal (parent.audience)
const KEYSET: KeySet = {
  issuer: "agent-A",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

// ── Fixed timestamps ──────────────────────────────────────────────────────────
//
//   T_ISSUED    ─── parent and delegation issued_at
//   T_NOW       ─── verification time (middle of all windows)
//   T_DEL_EXP   ─── delegation expiry (before parent)
//   T_PAR_EXP   ─── parent expiry
//
const T_ISSUED  = 1_000_000;
const T_NOW     = 1_001_000;
const T_DEL_EXP = 1_002_000;
const T_PAR_EXP = 1_003_000;

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeParent(overrides?: {
  expiry?: number;
  auth_id?: string;
  audience?: string;
  policy_id?: string;
}): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id:      overrides?.auth_id  ?? "f".repeat(64),
      issuer:       "pdp-issuer",
      audience:     overrides?.audience ?? "agent-A",
      intent_hash:  "a".repeat(64),
      state_hash:   "b".repeat(64),
      policy_id:    overrides?.policy_id ?? "policy-1",
      decision:     "ALLOW",
      issued_at:    T_ISSUED,
      expiry:       overrides?.expiry ?? T_PAR_EXP,
      kid:          "k1",
    },
    KEYS.privateKey
  );
}

// ── CASE 1: Core success case ─────────────────────────────────────────────────

test("CASE-1a: valid parent + valid delegation → ok", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-X"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegationChain(d, parent, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });

  assert.equal(result.ok, true);
  assert.equal(result.status, "ok");
  assert.equal(result.violations.length, 0);
});

test("CASE-1b: result carries policyId from delegation", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegationChain(d, parent, { now: T_NOW });

  assert.equal(result.policyId, "policy-1");
});

test("CASE-1c: isolated verifyDelegation (no parent) → ok", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });

  assert.equal(result.ok, true);
});

// ── CASE 2: Scope widening denied ─────────────────────────────────────────────

test("CASE-2a: scope.tools wider than parentScope → DELEGATION_SCOPE_VIOLATION", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-X", "tool-Y"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { tools: ["tool-X"] }, // tool-Y not in parent
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
  assert.ok(result.violations.some((v) => v.message?.includes("tool-Y")));
});

test("CASE-2b: scope.max_amount wider than parentScope → DELEGATION_SCOPE_VIOLATION", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { max_amount: 500n }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { max_amount: 100n },
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
  assert.ok(result.violations.some((v) => v.message?.includes("500") && v.message?.includes("100")));
});

test("CASE-2c: scope.max_actions wider than parentScope → DELEGATION_SCOPE_VIOLATION", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { max_actions: 50 }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { max_actions: 10 },
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
  assert.ok(result.violations.some((v) => v.message?.includes("max_actions")));
});

test("CASE-2d: scope.max_depth wider than parentScope → DELEGATION_SCOPE_VIOLATION", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { max_depth: 5 }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { max_depth: 2 },
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
  assert.ok(result.violations.some((v) => v.message?.includes("max_depth")));
});

test("CASE-2e: scope.tools equal to parentScope → ok (not wider)", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-X"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { tools: ["tool-X"] }, // equal is allowed
  });

  assert.equal(result.ok, true);
});

test("CASE-2f: scope.max_amount equal to parentScope → ok (not wider)", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { max_amount: 100n }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    parentScope: { max_amount: 100n }, // equal is allowed
  });

  assert.equal(result.ok, true);
});

// ── CASE 3: Expiry denied ─────────────────────────────────────────────────────

test("CASE-3a: delegation expired well before now → DELEGATION_EXPIRED", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_NOW - 100, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_EXPIRED"));
});

test("CASE-3b: delegation expiry === now → DELEGATION_EXPIRED (boundary: now >= expiry)", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_NOW, kid: "k1" }, // expiry == now
    KEYS.privateKey
  );

  const result = verifyDelegation(d, { now: T_NOW });

  // now >= expiry is the expiry condition — expiry exactly at now is expired
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_EXPIRED"));
});

test("CASE-3c: delegation expiry === now + 1 → ok (not yet expired)", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_NOW + 1, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, { now: T_NOW });

  assert.equal(result.ok, true);
});

test("CASE-3d: delegation.expiry > parent.expiry → DELEGATION_EXPIRY_EXCEEDS_PARENT", () => {
  const parent = makeParent({ expiry: T_DEL_EXP });
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP + 1, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegationChain(d, parent, { now: T_ISSUED + 1 });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_EXPIRY_EXCEEDS_PARENT"));
});

test("CASE-3e: parent already expired at verification time → DELEGATION_PARENT_EXPIRED", () => {
  const parent = makeParent({ expiry: T_NOW - 1 });
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_NOW - 1, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegationChain(d, parent, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_PARENT_EXPIRED"));
});

// ── CASE 4: Delegatee mismatch denied ─────────────────────────────────────────

test("CASE-4a: expectedDelegatee mismatch → DELEGATION_AUDIENCE_MISMATCH", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    expectedDelegatee: "agent-C", // artifact says agent-B
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_AUDIENCE_MISMATCH"));
});

test("CASE-4b: tampered delegator field → DELEGATION_DELEGATOR_MISMATCH", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  const tampered = { ...d, delegator: "agent-EVIL" };

  const result = verifyDelegationChain(tampered, parent, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_DELEGATOR_MISMATCH"));
});

// ── CASE 5: Parent binding mismatch denied ────────────────────────────────────

test("CASE-5a: delegation presented with wrong parentAuth → DELEGATION_PARENT_HASH_MISMATCH", () => {
  const parent = makeParent();
  const otherParent = makeParent({ auth_id: "e".repeat(64) });

  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  // Verify against a different parent than the one the delegation was bound to
  const result = verifyDelegationChain(d, otherParent, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_PARENT_HASH_MISMATCH"));
});

test("CASE-5b: tampered parent_auth_hash field → DELEGATION_PARENT_HASH_MISMATCH", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  const tampered = { ...d, parent_auth_hash: "0".repeat(64) };

  const result = verifyDelegationChain(tampered, parent, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_PARENT_HASH_MISMATCH"));
});

test("CASE-5c: multi-hop delegation denied — DelegationV1 as parent → DELEGATION_MULTIHOP_DENIED", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  // Attempt to re-delegate using a DelegationV1 as the parent
  const result = verifyDelegationChain(d, d as unknown as AuthorizationV1, { now: T_NOW });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_MULTIHOP_DENIED"));
});

// ── CASE 6: Invalid signature denied ─────────────────────────────────────────

test("CASE-6a: tampered delegatee → DELEGATION_SIGNATURE_INVALID", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  const tampered = { ...d, delegatee: "agent-EVIL" };

  const result = verifyDelegation(tampered, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SIGNATURE_INVALID"));
});

test("CASE-6b: tampered scope → DELEGATION_SIGNATURE_INVALID", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-X"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  // Widen scope after signing — signature should not cover the new scope
  const tampered = { ...d, scope: { tools: ["tool-X", "tool-Y", "tool-Z"] } };

  const result = verifyDelegation(tampered, {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SIGNATURE_INVALID"));
});

test("CASE-6c: requireSignatureVerification with no trustedKeySets → DELEGATION_TRUST_MISSING", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const result = verifyDelegation(d, {
    now: T_NOW,
    trustedKeySets: [],      // empty — no keysets available
    requireSignatureVerification: true,
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_TRUST_MISSING"));
});

test("CASE-6d: unknown kid → DELEGATION_KID_UNKNOWN", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const keysetWrongKid: KeySet = {
    issuer: "agent-A",
    version: "1",
    keys: [{ kid: "different-kid", alg: "Ed25519", public_key: KEYS.publicKey }],
  };

  const result = verifyDelegation(d, {
    now: T_NOW,
    trustedKeySets: keysetWrongKid,
    requireSignatureVerification: false, // kid lookup still runs
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_KID_UNKNOWN"));
});

// ── CASE 9: Determinism check ─────────────────────────────────────────────────

test("CASE-9a: delegationParentHash is stable — same input produces same output", () => {
  const parent = makeParent();
  const h1 = delegationParentHash(parent);
  const h2 = delegationParentHash(parent);
  const h3 = delegationParentHash(parent);

  assert.equal(h1, h2);
  assert.equal(h2, h3);
  assert.equal(h1.length, 64); // sha256 hex
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test("CASE-9b: delegationSigningPayload canonical bytes are stable across calls", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    {
      delegatee: "agent-B",
      scope: { tools: ["tool-X"], max_amount: 1000n },
      expiry: T_DEL_EXP,
      kid: "k1",
      delegationId: "fixed-id-determinism",
      issuedAt: T_ISSUED,
    },
    KEYS.privateKey
  );

  const bytes1 = canonicalJson(delegationSigningPayload(d));
  const bytes2 = canonicalJson(delegationSigningPayload(d));

  assert.equal(bytes1, bytes2);
  // Verify signature field is excluded from payload
  assert.ok(!bytes1.includes(d.signature), "signature must not appear in signing payload");
  // Verify delegation_id and key fields are present
  assert.ok(bytes1.includes("fixed-id-determinism"));
});

test("CASE-9c: createDelegation with fixed inputs produces identical signature on every call", () => {
  const parent = makeParent();
  const params = {
    delegatee: "agent-B",
    scope: { tools: ["tool-X"], max_amount: 500n },
    expiry: T_DEL_EXP,
    kid: "k1",
    delegationId: "fixed-id-sig-test",
    issuedAt: T_ISSUED,
  };

  const d1 = createDelegation(parent, params, KEYS.privateKey);
  const d2 = createDelegation(parent, params, KEYS.privateKey);

  // Ed25519 is deterministic: same key + same payload = same signature
  assert.equal(d1.signature, d2.signature);
  assert.equal(d1.parent_auth_hash, d2.parent_auth_hash);
  assert.equal(d1.delegation_id, d2.delegation_id);
});

test("CASE-9d: verifyDelegationChain is idempotent — same inputs, same result on repeated calls", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    {
      delegatee: "agent-B",
      scope: { tools: ["tool-X"] },
      expiry: T_DEL_EXP,
      kid: "k1",
      delegationId: "fixed-id-idempotent",
      issuedAt: T_ISSUED,
    },
    KEYS.privateKey
  );
  const opts = {
    now: T_NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  };

  const r1 = verifyDelegationChain(d, parent, opts);
  const r2 = verifyDelegationChain(d, parent, opts);
  const r3 = verifyDelegationChain(d, parent, opts);

  assert.equal(r1.ok, true);
  assert.equal(r1.ok, r2.ok);
  assert.equal(r2.ok, r3.ok);
  assert.equal(r1.status, r2.status);
  assert.equal(r1.policyId, r2.policyId);
  assert.equal(r1.violations.length, r2.violations.length);
});

test("CASE-9e: delegationParentHash changes when any parent field changes", () => {
  const base = makeParent();
  const variants: AuthorizationV1[] = [
    makeParent({ auth_id: "a".repeat(64) }),
    makeParent({ expiry: T_PAR_EXP + 1 }),
    makeParent({ audience: "agent-X" }),
    makeParent({ policy_id: "policy-OTHER" }),
  ];

  const baseHash = delegationParentHash(base);
  for (const v of variants) {
    assert.notEqual(
      delegationParentHash(v),
      baseHash,
      "hash must change when any parent field changes"
    );
  }
});
