// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based tests for DelegationV1 — @oxdeai/core.
 *
 * Uses the same seeded-PRNG approach as property.test.ts:
 *   - mulberry32 PRNG, fully deterministic given a seed
 *   - PBT_CASES env var controls iteration count (default 50)
 *   - PBT_SEED   env var overrides the base seed
 *   - PBT_ONLY_SEED env var runs a single seed for focused debugging
 *
 * Test IDs: D-P1 through D-P5.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import { createDelegation } from "../delegation/createDelegation.js";
import {
  verifyDelegation,
  verifyDelegationChain,
  delegationParentHash,
  delegationSigningPayload,
} from "../verification/verifyDelegation.js";
import { canonicalJson } from "../crypto/hashes.js";
import type { KeySet } from "../types/keyset.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { DelegationV1, DelegationScope } from "../types/delegation.js";

// ── PRNG ──────────────────────────────────────────────────────────────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "50");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260319");
const ONLY_SEED = process.env.PBT_ONLY_SEED ? Number(process.env.PBT_ONLY_SEED) : undefined;

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function randBigInt(rng: () => number, min: bigint, max: bigint): bigint {
  const range = Number(max - min);
  return min + BigInt(Math.floor(rng() * (range + 1)));
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[randInt(rng, 0, values.length - 1)];
}

function shuffle<T>(rng: () => number, input: readonly T[]): T[] {
  const out = [...input];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randInt(rng, 0, i);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── deepShuffle ───────────────────────────────────────────────────────────────
//
// Recursively reorders object keys at every nesting level, leaving values
// (including arrays) structurally intact.
//
// Rationale for NOT reordering arrays:
//   canonicalize() in hashes.ts preserves array order — arr.map(canonicalize).
//   Shuffling array elements would change the canonical JSON and therefore
//   the hash. deepShuffle is for validating key-order invariance only.

function deepShuffle(rng: () => number, value: unknown): unknown {
  if (Array.isArray(value)) {
    // Recurse into elements so nested objects inside arrays are shuffled,
    // but do NOT reorder the array itself.
    return value.map(item => deepShuffle(rng, item));
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of shuffle(rng, Object.keys(record))) {
      out[key] = deepShuffle(rng, record[key]);
    }
    return out;
  }
  return value;
}

// ── Fixed timestamps ───────────────────────────────────────────────────────────

const T_ISSUED   = 1_000_000;
const T_NOW      = 1_001_000;
const T_DEL_EXP  = 1_002_000;
const T_PAR_EXP  = 1_003_000;

// ── Fixed key material ────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "parent-agent",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

const TOOL_POOL = [
  "provision_gpu",
  "query_db",
  "send_payment",
  "transfer_tokens",
  "buy_storage",
  "mint_nft",
  "onchain_tx",
  "swap_asset",
] as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeParent(overrides?: Partial<{
  auth_id: string;
  audience: string;
  policy_id: string;
  expiry: number;
}>): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: overrides?.auth_id ?? "f".repeat(64),
      issuer: "pdp-issuer",
      audience: overrides?.audience ?? "parent-agent",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: overrides?.policy_id ?? "policy-1",
      decision: "ALLOW",
      issued_at: T_ISSUED,
      expiry: overrides?.expiry ?? T_PAR_EXP,
      kid: "k1",
    },
    KEYS.privateKey
  );
}

function makeChildScope(rng: () => number, parentTools: string[], parentMaxAmount: bigint): DelegationScope {
  // Pick a random non-empty subset of parentTools.
  const shuffled = shuffle(rng, parentTools);
  const n = randInt(rng, 1, shuffled.length);
  const tools = shuffled.slice(0, n);
  // Pick a max_amount <= parentMaxAmount.
  const max_amount = randBigInt(rng, 1n, parentMaxAmount);
  return { tools, max_amount };
}

// ── D-P1: parent hash is field-order invariant (deep shuffle) ─────────────────
//
// Validates two canonicalization invariants:
//
//   (a) delegationParentHash() is stable regardless of AuthorizationV1 key order.
//       This tests the canonical JSON used for hash binding.
//
//   (b) canonicalJson() of a DelegationV1 signing payload is stable regardless
//       of key order at any nesting level, including scope sub-fields.
//       AuthorizationV1 is flat; DelegationV1.scope is the meaningful nested
//       object here — this assertion exercises it.

test("D-P1: canonical hash is invariant to object key order at all nesting levels", () => {
  const parent = makeParent();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);

    // (a) AuthorizationV1: top-level key shuffle via deepShuffle.
    const shuffledParent = deepShuffle(rng, parent) as AuthorizationV1;
    assert.equal(
      delegationParentHash(parent),
      delegationParentHash(shuffledParent),
      `D-P1a seed=${seed}: delegationParentHash must be invariant to key order`
    );

    // (b) DelegationV1 signing payload: deepShuffle covers the nested scope
    //     object (max_amount, max_actions, max_depth, tools).
    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: { tools: ["provision_gpu", "query_db"], max_amount: 100n, max_actions: 5, max_depth: 2 },
        expiry: T_DEL_EXP,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const payload = delegationSigningPayload(delegation);
    const shuffledPayload = deepShuffle(rng, payload) as typeof payload;

    assert.equal(
      canonicalJson(payload),
      canonicalJson(shuffledPayload),
      `D-P1b seed=${seed}: DelegationV1 signing payload canonical JSON must be invariant to key order`
    );
  }
});

// ── D-P2: any strictly narrowing scope → verifyDelegationChain ok ─────────────

test("D-P2: any narrowing scope produces a valid delegation chain", () => {
  const parentTools = [...TOOL_POOL];
  const parentMaxAmount = 10_000n;
  const parent = makeParent();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const childScope = makeChildScope(rng, parentTools, parentMaxAmount);

    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: childScope,
        expiry: T_DEL_EXP,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const result = verifyDelegationChain(delegation, parent, {
      now: T_NOW,
      trustedKeySets: [KEYSET],
      requireSignatureVerification: true,
      expectedDelegatee: "child-agent",
    });

    assert.equal(
      result.ok,
      true,
      `D-P2 seed=${seed}: expected ok for scope ${JSON.stringify(childScope, (_k, v) =>
        typeof v === "bigint" ? v.toString() : v)}, got violations: ${JSON.stringify(result.violations)}`
    );
  }
});

// ── D-P3: delegation.expiry > parent.expiry → DELEGATION_EXPIRY_EXCEEDS_PARENT ─

test("D-P3: expiry exceeding parent always rejected", () => {
  const parent = makeParent();
  const fixedScope: DelegationScope = { tools: ["provision_gpu"], max_amount: 100n };

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const overExpiry = T_PAR_EXP + randInt(rng, 1, 10_000);

    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: fixedScope,
        expiry: overExpiry,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const result = verifyDelegationChain(delegation, parent, {
      now: T_NOW,
      trustedKeySets: [KEYSET],
      requireSignatureVerification: true,
    });

    assert.equal(result.ok, false, `D-P3 seed=${seed}: expected rejection for overExpiry=${overExpiry}`);
    assert.ok(
      result.violations.some(v => v.code === "DELEGATION_EXPIRY_EXCEEDS_PARENT"),
      `D-P3 seed=${seed}: expected DELEGATION_EXPIRY_EXCEEDS_PARENT, got ${JSON.stringify(result.violations)}`
    );
  }
});

// ── D-P4a: scope.max_amount widening → DELEGATION_SCOPE_VIOLATION ────────────

test("D-P4a: max_amount widening always rejected", () => {
  const parentMaxAmount = 500n;
  const parentTools = ["provision_gpu", "send_payment"];
  const parent = makeParent();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const extraAmount = randBigInt(rng, 1n, 1_000n);
    const wideScope: DelegationScope = {
      tools: parentTools,
      max_amount: parentMaxAmount + extraAmount,
    };

    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: wideScope,
        expiry: T_DEL_EXP,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const result = verifyDelegation(delegation, {
      now: T_NOW,
      trustedKeySets: [KEYSET],
      requireSignatureVerification: true,
      parentScope: { tools: parentTools, max_amount: parentMaxAmount },
    });

    assert.equal(result.ok, false, `D-P4a seed=${seed}: expected rejection for widened max_amount`);
    assert.ok(
      result.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"),
      `D-P4a seed=${seed}: expected DELEGATION_SCOPE_VIOLATION, got ${JSON.stringify(result.violations)}`
    );
  }
});

// ── D-P4b: scope.tools widening → DELEGATION_SCOPE_VIOLATION ─────────────────

test("D-P4b: tools widening always rejected", () => {
  const parentTools = ["provision_gpu", "send_payment"];
  const extraTools = TOOL_POOL.filter(t => !parentTools.includes(t));
  const parent = makeParent();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const extraTool = pick(rng, extraTools);
    const wideScope: DelegationScope = {
      tools: [...parentTools, extraTool],
    };

    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: wideScope,
        expiry: T_DEL_EXP,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const result = verifyDelegation(delegation, {
      now: T_NOW,
      trustedKeySets: [KEYSET],
      requireSignatureVerification: true,
      parentScope: { tools: parentTools },
    });

    assert.equal(result.ok, false, `D-P4b seed=${seed}: expected rejection for widened tools`);
    assert.ok(
      result.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"),
      `D-P4b seed=${seed}: expected DELEGATION_SCOPE_VIOLATION, got ${JSON.stringify(result.violations)}`
    );
  }
});

// ── D-P5: mutateRandomField + full mutation surface ───────────────────────────
//
// Validates that tampering with ANY field covered by the Ed25519 signature is
// always detected. The detection mechanism varies by field:
//
//   Chain-level checks (fire before signature, produce chain violation codes):
//     delegator       → DELEGATION_DELEGATOR_MISMATCH
//     policy_id       → DELEGATION_POLICY_ID_MISMATCH
//     parent_auth_hash → DELEGATION_PARENT_HASH_MISMATCH
//
//   Inner checks (reach signature verification, produce inner violation codes):
//     delegatee, audience, delegation_id, issued_at, expiry (lowered)
//     scope.tools (order matters in canonical JSON), scope.max_amount,
//     scope.max_actions, scope.max_depth
//                     → DELEGATION_SIGNATURE_INVALID
//
//     kid (wrong kid) → DELEGATION_KID_UNKNOWN
//     issuer          → DELEGATION_KID_UNKNOWN (issuer not in trusted keySets)
//
// All of these are "tamper detected" — the result must be ok=false with at
// least one violation from TAMPER_CODES.

// Violation codes that indicate tamper detection. Any mutation must produce
// at least one of these.
const TAMPER_CODES = new Set([
  "DELEGATION_SIGNATURE_INVALID",
  "DELEGATION_DELEGATOR_MISMATCH",
  "DELEGATION_POLICY_ID_MISMATCH",
  "DELEGATION_PARENT_HASH_MISMATCH",
  "DELEGATION_KID_UNKNOWN",
  "DELEGATION_ALG_UNSUPPORTED",
  "DELEGATION_MISSING_FIELD",
]);

// Base scope used for D-P5 delegations. All scope sub-fields are populated
// so that mutations to scope.max_actions and scope.max_depth change
// the canonical JSON (they go from present→changed, not absent→present).
const D5_SCOPE: DelegationScope = {
  tools: ["provision_gpu", "query_db"],
  max_amount: 100n,
  max_actions: 10,
  max_depth: 3,
};

type NamedMutation = {
  target: string;
  apply: (d: DelegationV1) => DelegationV1;
};

// Each mutation changes exactly one field post-signing. Mutations are chosen
// to always produce a different value (no identity mutations).
//
// Notes on specific fields:
//   expiry: lowered by 1 (T_DEL_EXP - 1 = 1_001_999 > T_NOW = 1_001_000,
//           still valid temporally, still ≤ T_PAR_EXP) → signature-only catch.
//   scope.tools: ["query_db","provision_gpu"] is the reversed order of the
//           original ["provision_gpu","query_db"]. Arrays are order-sensitive
//           in canonical JSON, so this changes the signed payload.
//   kid: changed to "evil-kid" not present in KEYSET → DELEGATION_KID_UNKNOWN.
//   issuer: changed so KEYSET.issuer ("parent-agent") no longer matches →
//           findKeyInKeySets fails → DELEGATION_KID_UNKNOWN.
const MUTATIONS: NamedMutation[] = [
  {
    target: "delegation_id",
    apply: d => ({ ...d, delegation_id: "00000000-0000-0000-0000-000000000000" }),
  },
  {
    target: "issuer",
    apply: d => ({ ...d, issuer: d.issuer + "-evil" }),
  },
  {
    target: "audience",
    apply: d => ({ ...d, audience: d.audience + "-evil" }),
  },
  {
    target: "parent_auth_hash",
    apply: d => ({
      ...d,
      parent_auth_hash: (d.parent_auth_hash[0] === "a" ? "b" : "a") + d.parent_auth_hash.slice(1),
    }),
  },
  {
    target: "delegator",
    apply: d => ({ ...d, delegator: "evil-delegator" }),
  },
  {
    target: "delegatee",
    apply: d => ({ ...d, delegatee: "evil-agent" }),
  },
  {
    target: "policy_id",
    apply: d => ({ ...d, policy_id: "evil-policy" }),
  },
  {
    target: "issued_at",
    apply: d => ({ ...d, issued_at: d.issued_at + 1 }),
  },
  {
    target: "expiry",
    apply: d => ({ ...d, expiry: d.expiry - 1 }),
  },
  {
    target: "scope.tools:reorder",
    // Reverse array order — canonical JSON is order-sensitive for arrays.
    apply: d => ({
      ...d,
      scope: { ...d.scope, tools: ["query_db", "provision_gpu"] },
    }),
  },
  {
    target: "scope.tools:duplicate",
    // Append a copy of the first tool: ["provision_gpu","query_db","provision_gpu"].
    //
    // Why this matters:
    //   canonicalJson() maps arrays as value.map(canonicalize) with no
    //   deduplication. A duplicated entry produces a strictly longer canonical
    //   JSON string than the original, so the Ed25519 signature fails.
    //
    //   This tests two assumptions in one:
    //   (a) Canonicalization equality: the verifier MUST NOT deduplicate or
    //       normalize scope.tools before computing the signing payload. If it
    //       did, a tampered artifact with duplicates would pass verification.
    //   (b) Scope-check vs. signature mismatch: scope.tools.includes("provision_gpu")
    //       still returns true for the duplicated array, so guard-level scope
    //       enforcement alone would not catch this mutation. Only the signature
    //       check closes the gap — which is exactly the invariant D-P5 asserts.
    apply: d => ({
      ...d,
      scope: {
        ...d.scope,
        tools: d.scope.tools !== undefined && d.scope.tools.length > 0
          ? [...d.scope.tools, d.scope.tools[0]]
          : d.scope.tools,
      },
    }),
  },
  {
    target: "scope.max_amount",
    apply: d => ({
      ...d,
      scope: { ...d.scope, max_amount: (d.scope.max_amount ?? 0n) + 1n },
    }),
  },
  {
    target: "scope.max_actions",
    apply: d => ({
      ...d,
      scope: { ...d.scope, max_actions: (d.scope.max_actions ?? 0) + 1 },
    }),
  },
  {
    target: "scope.max_depth",
    apply: d => ({
      ...d,
      scope: { ...d.scope, max_depth: (d.scope.max_depth ?? 0) + 1 },
    }),
  },
  {
    target: "kid",
    apply: d => ({ ...d, kid: "evil-kid" }),
  },
];

function mutateRandomField(rng: () => number, delegation: DelegationV1): { tampered: DelegationV1; target: string } {
  const mutation = pick(rng, MUTATIONS);
  return { tampered: mutation.apply(delegation), target: mutation.target };
}

test("D-P5: mutating any signed field is always detected", () => {
  const parent = makeParent();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);

    const delegation = createDelegation(
      parent,
      {
        delegatee: "child-agent",
        scope: D5_SCOPE,
        expiry: T_DEL_EXP,
        kid: "k1",
        issuedAt: T_ISSUED,
      },
      KEYS.privateKey
    );

    const { tampered, target } = mutateRandomField(rng, delegation);

    const result = verifyDelegationChain(tampered, parent, {
      now: T_NOW,
      trustedKeySets: [KEYSET],
      requireSignatureVerification: true,
      // No parentScope — we are testing signature coverage, not scope narrowing.
    });

    // Invariant:
    // Any mutation to any signed field MUST invalidate the delegation.
    // The exact failure code may vary depending on which verification layer
    // detects it first.

    assert.equal(
      result.ok,
      false,
      `D-P5 seed=${seed} target=${target}: result.ok must be false after mutation`
    );
    assert.ok(
      result.violations.some(v => TAMPER_CODES.has(v.code)),
      `D-P5 seed=${seed} target=${target}: at least one violation must belong to TAMPER_CODES, ` +
      `got: ${JSON.stringify(result.violations)}`
    );
  }
});
