/**
 * delegation.ts — Inline DelegationV1 implementation
 *
 * Self-contained for this demo. These functions will move to @oxdeai/core
 * when DelegationV1 ships as part of the v2.x protocol milestone.
 *
 * Implements the spec at: docs/spec/delegation-v1.md
 */

import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";

// ── Types ─────────────────────────────────────────────────────────────────────

export type DelegationScope = {
  tools: string[];       // subset of parent allowed tools
  max_amount: number;    // <= parent scope
  max_actions?: number;
};

export type DelegationV1 = {
  delegation_id:    string;
  issuer:           string;
  delegator:        string;   // MUST match parent auth audience
  delegatee:        string;   // the child agent receiving authority
  parent_auth_hash: string;   // SHA-256 hex of parent AuthorizationV1
  scope:            DelegationScope;
  policy_id:        string;
  issued_at:        number;   // unix ms
  expiry:           number;   // unix ms, MUST be <= parent expiry
  alg:              "EdDSA";
  kid:              string;
  signature:        string;   // base64 Ed25519
};

export type ParentAuth = {
  auth_id:       string;
  issuer:        string;
  audience:      string;
  policy_id:     string;
  allowed_tools: string[];
  max_amount:    number;
  expiry:        number;   // unix ms
};

export type DelegationVerifyResult =
  | { ok: true }
  | { ok: false; reason: string };

// ── Key management ────────────────────────────────────────────────────────────

export type DelegationKeyPair = {
  kid:           string;
  privateKeyPem: string;
  publicKeyPem:  string;
};

export function generateDemoKeyPair(kid: string): DelegationKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    kid,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKeyPem:  publicKey.export({ type: "spki",  format: "pem" }) as string,
  };
}

// ── Canonical helpers ─────────────────────────────────────────────────────────

const SIGNING_DOMAIN = "OXDEAI_DELEGATION_V1";

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortedJson(value));
}

function sortedJson(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortedJson);
  const obj = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(obj).sort().map((k) => [k, sortedJson(obj[k])])
  );
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function signingInput(payload: unknown): Buffer {
  const prefix = Buffer.from(`${SIGNING_DOMAIN}\n`, "utf8");
  const body   = Buffer.from(canonicalJson(payload), "utf8");
  return Buffer.concat([prefix, body]);
}

export function hashParentAuth(parent: ParentAuth): string {
  return sha256Hex(canonicalJson(parent));
}

// ── Create + sign ─────────────────────────────────────────────────────────────

export function createDelegation(
  parent:     ParentAuth,
  delegatee:  string,
  scope:      DelegationScope,
  expiry:     number,
  keyPair:    DelegationKeyPair,
  now:        number = Date.now()
): DelegationV1 {
  const unsigned: Omit<DelegationV1, "signature"> = {
    delegation_id:    crypto.randomUUID(),
    issuer:           parent.issuer,
    delegator:        parent.audience,
    delegatee,
    parent_auth_hash: hashParentAuth(parent),
    scope,
    policy_id:        parent.policy_id,
    issued_at:        now,
    expiry,
    alg:              "EdDSA",
    kid:              keyPair.kid,
  };

  const privKey = createPrivateKey(keyPair.privateKeyPem);
  const sig = sign(null, signingInput(unsigned), privKey);

  return { ...unsigned, signature: sig.toString("base64") };
}

// ── Verify ────────────────────────────────────────────────────────────────────

export function verifyDelegation(
  delegation:     DelegationV1,
  parent:         ParentAuth,
  executingAgent: string,
  tool:           string,
  amount:         number,
  publicKeyPem:   string,
  now:            number = Date.now()
): DelegationVerifyResult {

  // 1. Signature
  const { signature, ...unsigned } = delegation;
  const pubKey = createPublicKey(publicKeyPem);
  const sigBuf = Buffer.from(signature, "base64");
  const valid  = verify(null, signingInput(unsigned), pubKey, sigBuf);
  if (!valid) return { ok: false, reason: "invalid signature" };

  // 2. Parent hash binding
  const expectedHash = hashParentAuth(parent);
  if (delegation.parent_auth_hash !== expectedHash) {
    return { ok: false, reason: "parent_auth_hash mismatch" };
  }

  // 3. Parent expiry
  if (parent.expiry < now) return { ok: false, reason: "parent authorization expired" };

  // 4. Delegator binding
  if (delegation.delegator !== parent.audience) {
    return { ok: false, reason: "delegator does not match parent audience" };
  }

  // 5. Policy binding
  if (delegation.policy_id !== parent.policy_id) {
    return { ok: false, reason: "policy_id mismatch" };
  }

  // 6. Delegation expiry
  if (delegation.expiry < now) return { ok: false, reason: "delegation expired" };
  if (delegation.expiry > parent.expiry) {
    return { ok: false, reason: "expiry exceeds parent expiry" };
  }

  // 7. Delegatee binding
  if (delegation.delegatee !== executingAgent) {
    return { ok: false, reason: `delegatee mismatch: expected ${delegation.delegatee}, got ${executingAgent}` };
  }

  // 8. Scope: tool allowlist
  if (!delegation.scope.tools.includes(tool)) {
    return { ok: false, reason: `tool '${tool}' not in delegation scope: [${delegation.scope.tools.join(", ")}]` };
  }

  // 9. Scope: amount
  if (amount > delegation.scope.max_amount) {
    return { ok: false, reason: `amount ${amount} exceeds delegation max_amount ${delegation.scope.max_amount}` };
  }

  // 10. Scope: tool must be in parent allowed_tools
  if (!parent.allowed_tools.includes(tool)) {
    return { ok: false, reason: `tool '${tool}' not in parent allowed_tools` };
  }

  return { ok: true };
}
