# DelegationV1 Implementation Plan

## Status

Non-normative (developer documentation)






**Target:** `@oxdeai/core` + `@oxdeai/guard`
**Depends on:** DelegationV1 spec (`docs/spec/delegation-v1.md`), AuthorizationV1

---

## 1. Directory Structure

```
packages/core/src/
├── types/
│   ├── authorization.ts          ← extend: add DelegationV1 type
│   └── delegation.ts             ← NEW: DelegationV1, DelegationScope types
├── crypto/
│   └── signatures.ts             ← extend: add DELEGATION_V1 signing domain
├── verification/
│   ├── verifyAuthorization.ts    ← no change
│   └── verifyDelegation.ts       ← NEW: verifyDelegation()
├── delegation/
│   ├── createDelegation.ts       ← NEW: createDelegation(), signDelegation()
│   └── index.ts                  ← NEW: exports
└── index.ts                      ← extend: export delegation surface

packages/guard/src/
├── guard.ts                      ← extend: accept AuthorizationV1 | DelegationV1
├── types.ts                      ← extend: OxDeAIGuardConfig delegation options
└── errors.ts                     ← no change
```

Total: **4 new files**, **4 files extended**, **0 breaking changes**.

---

## 2. Core Types

**`packages/core/src/types/delegation.ts`** - new file

```typescript
export type DelegationScope = {
  tools?: string[];        // subset of parent allowed tools
  max_amount?: number;     // <= parent amount
  max_actions?: number;    // freely set (no parent equivalent)
  max_depth?: number;      // <= parent max_depth if parent defines one
};

export type DelegationV1 = {
  delegation_id: string;       // unique nonce, UUID v4 recommended
  issuer: string;              // system that produced this artifact
  delegator: string;           // MUST match parent AuthorizationV1.audience
  delegatee: string;           // recipient of delegated authority
  parent_auth_hash: string;    // SHA-256 hex of canonical parent AuthorizationV1
  scope: DelegationScope;
  policy_id: string;           // MUST match parent AuthorizationV1.policy_id
  issued_at: number;           // unix ms
  expiry: number;              // unix ms, MUST be <= parent expiry
  alg: "EdDSA";
  kid: string;
  signature: string;           // base64url Ed25519 over canonical signing input
};
```

**Extend `packages/core/src/types/authorization.ts`:**

```typescript
// Add at bottom - no changes to AuthorizationV1
export type AuthorizationCredential = AuthorizationV1 | DelegationV1;

export function isDelegationV1(
  credential: AuthorizationCredential
): credential is DelegationV1 {
  return "delegation_id" in credential && "parent_auth_hash" in credential;
}
```

---

## 3. Signing Domain

**Extend `packages/core/src/crypto/signatures.ts`:**

```typescript
export const SIGNING_DOMAINS = {
  AUTH_V1:        "OXDEAI_AUTH_V1",
  ENVELOPE_V1:    "OXDEAI_ENVELOPE_V1",
  CHECKPOINT_V1:  "OXDEAI_CHECKPOINT_V1",
  DELEGATION_V1:  "OXDEAI_DELEGATION_V1",   // ← add
} as const;
```

The existing `signEd25519(domain, payload, privateKeyPem)` and `verifyEd25519(domain, payload, sig, publicKeyPem)` work unchanged - just pass `SIGNING_DOMAINS.DELEGATION_V1`.

Signing payload = `DelegationV1` object with `signature` field omitted.

---

## 4. `createDelegation()` and `signDelegation()`

**`packages/core/src/delegation/createDelegation.ts`** - new file

```typescript
import { createHash, randomUUID } from "node:crypto";
import { AuthorizationV1 } from "../types/authorization.js";
import { DelegationV1, DelegationScope } from "../types/delegation.js";
import { canonicalJson } from "../crypto/hashes.js";
import { signEd25519, SIGNING_DOMAINS } from "../crypto/signatures.js";

export type CreateDelegationOptions = {
  issuer: string;
  delegator: string;   // must match parent.audience - caller is responsible
  delegatee: string;
  scope: DelegationScope;
  kid: string;
  expiry: number;      // unix ms, caller must ensure <= parent.expiry
  now?: number;        // injectable for determinism
};

/**
 * Build and sign a DelegationV1 from a resolved parent AuthorizationV1.
 * Does NOT enforce invariants - call verifyDelegation() after to confirm.
 */
export function createDelegation(
  parent: AuthorizationV1,
  opts: CreateDelegationOptions,
  privateKeyPem: string
): DelegationV1 {
  const parent_auth_hash = sha256OfAuth(parent);
  const now = opts.now ?? Date.now();

  const unsigned: Omit<DelegationV1, "signature"> = {
    delegation_id: randomUUID(),
    issuer:         opts.issuer,
    delegator:      opts.delegator,
    delegatee:      opts.delegatee,
    parent_auth_hash,
    scope:          opts.scope,
    policy_id:      parent.policy_id,
    issued_at:      now,
    expiry:         opts.expiry,
    alg:            "EdDSA",
    kid:            opts.kid,
  };

  const signature = signEd25519(
    SIGNING_DOMAINS.DELEGATION_V1,
    unsigned,
    privateKeyPem
  );

  return { ...unsigned, signature };
}

/**
 * Sign an already-built DelegationV1 (missing signature field).
 */
export function signDelegation(
  unsigned: Omit<DelegationV1, "signature">,
  privateKeyPem: string
): DelegationV1 {
  const signature = signEd25519(
    SIGNING_DOMAINS.DELEGATION_V1,
    unsigned,
    privateKeyPem
  );
  return { ...unsigned, signature };
}

function sha256OfAuth(auth: AuthorizationV1): string {
  return createHash("sha256").update(canonicalJson(auth), "utf8").digest("hex");
}
```

---

## 5. `verifyDelegation()`

**`packages/core/src/verification/verifyDelegation.ts`** - new file

```typescript
import { AuthorizationV1 } from "../types/authorization.js";
import { DelegationV1 } from "../types/delegation.js";
import { KeySet } from "../types/keyset.js";
import { VerificationResult } from "./types.js";
import { verifyEd25519, SIGNING_DOMAINS } from "../crypto/signatures.js";
import { canonicalJson } from "../crypto/hashes.js";
import { createHash } from "node:crypto";

export type VerifyDelegationOptions = {
  now?: number;
  trustedKeySets?: KeySet | readonly KeySet[];
  consumedDelegationIds?: readonly string[];
};

export function verifyDelegation(
  delegation: DelegationV1,
  parent: AuthorizationV1,
  opts: VerifyDelegationOptions = {}
): VerificationResult {
  const violations: string[] = [];
  const now = opts.now ?? Date.now();

  // Step 1: Structural check
  for (const field of REQUIRED_FIELDS) {
    if ((delegation as Record<string, unknown>)[field] == null) {
      violations.push(`missing required field: ${field}`);
    }
  }
  if (violations.length) return deny(violations);

  // Step 2: Signature verification
  const keyPem = resolveKey(delegation.kid, delegation.issuer, opts.trustedKeySets);
  if (!keyPem) return deny(["unknown kid: " + delegation.kid]);

  const { signature, ...unsigned } = delegation;
  const valid = verifyEd25519(SIGNING_DOMAINS.DELEGATION_V1, unsigned, signature, keyPem);
  if (!valid) return deny(["invalid signature"]);

  // Step 3: Parent hash binding
  const computedHash = sha256OfAuth(parent);
  if (computedHash !== delegation.parent_auth_hash) {
    return deny(["parent_auth_hash mismatch"]);
  }

  // Step 4: Single-hop enforcement
  // (DelegationV1 cannot be a parent - enforced by type system + this check)
  if ("delegation_id" in (parent as object)) {
    return deny(["multi-hop delegation not permitted"]);
  }

  // Step 5: Parent expiry
  if (parent.expiry < now) return deny(["parent authorization expired"]);

  // Step 6: Delegator binding
  if (delegation.delegator !== parent.audience) {
    return deny(["delegator does not match parent audience"]);
  }

  // Step 7: Policy binding
  if (delegation.policy_id !== parent.policy_id) {
    return deny(["policy_id mismatch"]);
  }

  // Step 8: Expiry
  if (delegation.expiry > parent.expiry) return deny(["expiry exceeds parent expiry"]);
  if (delegation.expiry <= delegation.issued_at) return deny(["expiry before issued_at"]);
  if (delegation.expiry < now) return deny(["delegation expired"]);

  // Step 9: Scope narrowing
  const scopeViolations = checkScopeNarrowing(delegation, parent);
  if (scopeViolations.length) return deny(scopeViolations);

  // Step 10: Replay
  if (opts.consumedDelegationIds?.includes(delegation.delegation_id)) {
    return deny(["delegation_id already consumed"]);
  }

  return { ok: true, status: "ok", violations: [] };
}

// --- Helpers ---

function deny(violations: string[]): VerificationResult {
  return { ok: false, status: "invalid", violations };
}

function checkScopeNarrowing(d: DelegationV1, parent: AuthorizationV1): string[] {
  const v: string[] = [];

  if (d.scope.max_amount != null) {
    // parent.amount is in bigint-equivalent units - compare numerically
    const parentAmount = typeof parent.amount === "bigint"
      ? Number(parent.amount) / 1_000_000
      : (parent.amount ?? Infinity);
    if (d.scope.max_amount > parentAmount) {
      v.push("scope.max_amount exceeds parent amount");
    }
  }

  if (d.scope.tools != null) {
    const parentTools: string[] = (parent as Record<string, unknown>).allowed_tools as string[] ?? [];
    const notAllowed = d.scope.tools.filter(t => !parentTools.includes(t));
    if (notAllowed.length) {
      v.push(`scope.tools not subset of parent: ${notAllowed.join(", ")}`);
    }
  }

  if (d.scope.max_depth != null) {
    const parentDepth = (parent as Record<string, unknown>).max_depth as number | undefined;
    if (parentDepth != null && d.scope.max_depth > parentDepth) {
      v.push("scope.max_depth exceeds parent max_depth");
    }
  }

  return v;
}

function resolveKey(
  kid: string,
  issuer: string,
  keySets?: KeySet | readonly KeySet[]
): string | null {
  if (!keySets) return null;
  const sets = Array.isArray(keySets) ? keySets : [keySets];
  for (const ks of sets) {
    if (ks.issuer !== issuer) continue;
    const key = ks.keys.find(k => k.kid === kid && k.status !== "revoked");
    if (key) return key.public_key;
  }
  return null;
}

function sha256OfAuth(auth: AuthorizationV1): string {
  return createHash("sha256").update(canonicalJson(auth), "utf8").digest("hex");
}

const REQUIRED_FIELDS = [
  "delegation_id", "issuer", "delegator", "delegatee",
  "parent_auth_hash", "scope", "policy_id",
  "issued_at", "expiry", "alg", "kid", "signature",
] as const;
```

---

## 6. Guard Integration

**Extend `packages/guard/src/types.ts`:**

```typescript
import { DelegationV1 } from "@oxdeai/core";
import { KeySet } from "@oxdeai/core";

// Add to OxDeAIGuardConfig
export type OxDeAIGuardConfig = {
  // ... existing fields unchanged ...

  /**
   * Optional: resolve a parent AuthorizationV1 by hash.
   * Required when the guard should accept DelegationV1 credentials.
   * Must return null if the parent cannot be resolved.
   */
  resolveParentAuthorization?: (
    parentAuthHash: string
  ) => AuthorizationV1 | null | Promise<AuthorizationV1 | null>;

  /**
   * Optional: trusted KeySets for delegation signature verification.
   */
  delegationKeySets?: KeySet | readonly KeySet[];

  /**
   * Optional: set of consumed delegation IDs for replay protection.
   */
  consumedDelegationIds?: readonly string[];
};
```

**Extend `packages/guard/src/guard.ts`** - add delegation branch after authorization check:

```typescript
import { isDelegationV1, verifyDelegation } from "@oxdeai/core";

// In the guard function, after engine.evaluatePure() returns ALLOW:

const credential = result.authorization; // AuthorizationV1 | DelegationV1 | undefined

if (!credential) {
  throw new OxDeAIAuthorizationError("No authorization credential. Execution blocked.");
}

if (isDelegationV1(credential)) {
  // Delegation path
  if (!config.resolveParentAuthorization) {
    throw new OxDeAIAuthorizationError(
      "DelegationV1 presented but resolveParentAuthorization is not configured."
    );
  }
  const parent = await config.resolveParentAuthorization(credential.parent_auth_hash);
  if (!parent) {
    throw new OxDeAIAuthorizationError(
      "DelegationV1 parent authorization could not be resolved. Execution blocked."
    );
  }
  const delegationCheck = verifyDelegation(credential, parent, {
    now: Date.now(),
    trustedKeySets: config.delegationKeySets,
    consumedDelegationIds: config.consumedDelegationIds,
  });
  if (!delegationCheck.ok) {
    throw new OxDeAIAuthorizationError(
      `DelegationV1 verification failed: ${delegationCheck.violations.join(", ")}. Execution blocked.`
    );
  }
} else {
  // Existing AuthorizationV1 path - unchanged
  const authCheck = config.engine.verifyAuthorization(intent, credential, nextState, now);
  if (!authCheck.valid) {
    throw new OxDeAIAuthorizationError(
      `Authorization verification failed: ${authCheck.reason ?? "unknown reason"}. Execution blocked.`
    );
  }
}
```

The existing `AuthorizationV1` path is **untouched**. `isDelegationV1()` discriminates at runtime with zero overhead on the happy path.

---

## 7. Exports

**`packages/core/src/delegation/index.ts`** - new file

```typescript
export { createDelegation, signDelegation } from "./createDelegation.js";
export type { CreateDelegationOptions } from "./createDelegation.js";
```

**Extend `packages/core/src/index.ts`:**

```typescript
export * from "./delegation/index.js";
export { verifyDelegation } from "./verification/verifyDelegation.js";
export type { VerifyDelegationOptions } from "./verification/verifyDelegation.js";
export type { DelegationV1, DelegationScope } from "./types/delegation.js";
export { isDelegationV1 } from "./types/authorization.js";
```

---

## 8. Implementation Order

```
1. packages/core/src/types/delegation.ts              - types first
2. packages/core/src/types/authorization.ts           - add isDelegationV1, AuthorizationCredential
3. packages/core/src/crypto/signatures.ts             - add DELEGATION_V1 domain
4. packages/core/src/delegation/createDelegation.ts   - create + sign
5. packages/core/src/verification/verifyDelegation.ts - verify
6. packages/core/src/delegation/index.ts              - exports
7. packages/core/src/index.ts                         - surface exports
8. packages/guard/src/types.ts                        - config extension
9. packages/guard/src/guard.ts                        - delegation branch
10. tests                                             - see §9
```

---

## 9. Tests

**`packages/core/src/test/delegation.test.ts`** - new file, cover:

- `createDelegation()` produces valid artifact
- `verifyDelegation()` returns ok on valid chain
- DENY on expired delegation
- DENY on parent hash mismatch
- DENY on scope expansion (amount, tools, depth)
- DENY on delegator mismatch
- DENY on multi-hop attempt
- DENY on invalid signature
- DENY on consumed delegation_id

**`packages/guard/src/test/guard-delegation.test.ts`** - new file, cover:

- Guard accepts valid DelegationV1 and calls execute
- Guard throws OxDeAIAuthorizationError on invalid delegation
- Guard throws OxDeAIAuthorizationError if resolveParentAuthorization returns null
- Guard throws OxDeAIAuthorizationError if resolveParentAuthorization not configured

---

## 10. What Does Not Change

- `AuthorizationV1` schema - no field changes
- `PolicyEngine` evaluation logic
- `verifyAuthorization()` - untouched
- `OxDeAIGuard` default behavior - delegation is opt-in via `resolveParentAuthorization`
- All existing adapter packages - no changes required
- Conformance vectors - no existing vectors are invalidated

---

## 11. References

- [`docs/spec/delegation-v1.md`](./delegation-v1.md)
- [`packages/core/src/types/authorization.ts`](../../packages/core/src/types/authorization.ts)
- [`packages/core/src/crypto/signatures.ts`](../../packages/core/src/crypto/signatures.ts)
- [`packages/core/src/verification/verifyAuthorization.ts`](../../packages/core/src/verification/verifyAuthorization.ts)
- [`packages/guard/src/guard.ts`](../../packages/guard/src/guard.ts)
