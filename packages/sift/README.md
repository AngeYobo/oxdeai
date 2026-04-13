# @oxdeai/sift

Sift adapter for OxDeAI.

This package converts a **Sift governance receipt** into deterministic OxDeAI authorization inputs:

```text
Sift receipt
→ local verification
→ intent normalization
→ state normalization
→ AuthorizationV1 construction
````

It does **not** execute actions and it does **not** treat a Sift receipt as execution authorization.

## Purpose

Sift is an upstream **decision / governance layer**.

OxDeAI is the **execution-time authorization and enforcement layer**.

This adapter bridges the two without weakening OxDeAI invariants:

* no valid authorization → no execution
* fail-closed on ambiguity
* deterministic intent/state binding
* local verification at execution time
* no runtime dependency on remote receipt verification

## What this package does

### `verifyReceipt`

Validates and verifies a Sift receipt locally.

Responsibilities:

* structural validation
* receipt version validation
* bounded freshness validation (`maxAgeMs` — configurable per deployment; treat as a security parameter)
* `ALLOW` / `DENY` handling
* receipt hash integrity validation
* local Ed25519 signature verification

Properties:

* fail-closed
* no network calls
* explicit typed errors
* deterministic behavior

### `normalizeIntent`

Transforms explicit execution parameters plus a verified Sift receipt into a deterministic OxDeAI intent object.

Properties:

* no receipt-only execution path
* no implicit defaults
* no hidden coercion
* safe integers only
* rejects non-deterministic runtime objects
* prototype-safe object construction

### `normalizeState`

Validates and normalizes explicit execution-relevant state.

Properties:

* state must be supplied explicitly
* no inferred or default state
* deterministic normalized output
* required top-level keys supported
* prototype-safe object construction

### `receiptToAuthorization`

Builds an unsigned `AuthorizationV1`-style payload from:

* verified Sift receipt
* normalized intent
* normalized state
* explicit issuer / audience bindings

Explicit bindings:

| Authorization field | Source                          |
| ------------------- | ------------------------------- |
| `auth_id`           | `receipt.nonce`                 |
| `policy_id`         | `receipt.policy_matched`        |
| `intent_hash`       | SHA-256 of canonicalized intent |
| `state_hash`        | SHA-256 of canonicalized state  |
| `issued_at`         | single captured adapter time    |
| `expires_at`        | derived from configured TTL     |
| `audience`          | caller-supplied                 |
| `issuer`            | caller-supplied                 |

This file constructs the authorization payload. It does **not** sign it.

## What this package does not do

This package does **not**:

* call Sift `/verify-receipt` at runtime
* execute actions
* enforce at the PEP boundary
* fetch state from external systems
* infer missing execution parameters
* treat Sift receipts as portable execution authorization

## Security model

This package is designed around OxDeAI’s execution-boundary model.

### Important constraint

A Sift receipt is a **governance decision artifact**.

It is **not** an OxDeAI authorization artifact.

Execution must remain gated by valid `AuthorizationV1` verified at the PEP boundary.

### Fail-closed behavior

Any ambiguity or invalid input results in failure.

Examples:

* malformed receipt
* invalid signature
* stale receipt
* unsupported param/state type
* missing issuer / audience
* failed canonical hashing

### Freshness window

The adapter enforces a bounded freshness window on Sift receipts.

- Default: 30 seconds
- MUST be configurable per deployment
- MUST be treated as a security parameter, not a convenience value

A shorter window reduces replay exposure but increases sensitivity to clock skew and network latency.

The adapter MUST reject:
- stale receipts (age > configured window)
- receipts too far in the future (beyond allowed clock skew)

### Receipt hash integrity

`receipt_hash` MUST be computed over the canonical JSON payload with:

- `signature` excluded
- `receipt_hash` excluded

Canonicalization requirements:
- lexicographic key ordering
- no whitespace
- UTF-8 encoding

The adapter MUST:

1. recompute the hash locally
2. compare with the provided `receipt_hash`
3. only proceed if they match

### Signature verification scope

The Ed25519 signature is verified over the canonical payload with:

- `signature` excluded
- `receipt_hash` INCLUDED

This enforces the sequence:

```text
payload → integrity check (receipt_hash) → signature verification
```

The adapter MUST NOT:
- verify signature before validating `receipt_hash`
- mutate payload before verification

### Verification ordering

The adapter MUST perform verification in the following order:

1. `receipt_hash` integrity validation
2. signature verification
3. semantic validation (decision, freshness, replay prechecks, etc.)

The adapter MUST NOT proceed to a later step if an earlier step fails.

### Key management and rotation

The adapter verifies Sift receipts using trusted Ed25519 public keys.

Production deployments SHOULD support key rotation via a key set:

- multiple public keys identified by `kid`
- deterministic key selection
- ability to revoke keys without downtime

Minimum requirements:

- support multiple active keys
- fail closed if key cannot be resolved
- no fallback guessing

If the receipt includes a key identifier (`kid`), it MUST be used to select the correct key.

If the receipt does not include a `kid`, key selection MUST be deterministic and externally configured.

If no matching key is found:
→ verification MUST fail

### Prototype safety

All user-controlled normalized objects are created with `Object.create(null)`.

This prevents `__proto__` setter side effects and silent key loss during normalization.

## Package structure

```text
packages/sift/
├── src/
│   ├── verifyReceipt.ts
│   ├── normalizeIntent.ts
│   ├── state.ts
│   ├── receiptToAuthorization.ts
│   └── index.ts
├── test/
├── package.json
└── tsconfig.json
```

## API surface

### Receipt verification

```ts
import { verifyReceipt } from "@oxdeai/sift";
```

Verifies:

* structure
* freshness
* receipt hash
* Ed25519 signature

### Intent normalization

```ts
import { normalizeIntent } from "@oxdeai/sift";
```

Builds:

```json
{
  "type": "EXECUTE",
  "tool": "<receipt.tool>",
  "params": { "...": "..." }
}
```

### State normalization

```ts
import { normalizeState } from "@oxdeai/sift";
```

Builds a deterministic state object suitable for later canonicalization and hashing.

### Authorization construction

```ts
import { receiptToAuthorization } from "@oxdeai/sift";
```

Builds an unsigned `AuthorizationV1` payload plus signing payload.

## Example

```ts
import {
  verifyReceipt,
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
} from "@oxdeai/sift";

const verified = verifyReceipt(receipt, {
  publicKeyPem,
  requireAllowDecision: true,
  maxAgeMs: 30_000, // configurable per deployment; treat as a security parameter
});

if (!verified.ok) {
  throw new Error(`${verified.code}: ${verified.message}`);
}

const intentResult = normalizeIntent({
  receipt: verified.receipt,
  params: {
    amount: 500,
    currency: "USD",
    destination: "acct_9f3a",
  },
});

if (!intentResult.ok) {
  throw new Error(`${intentResult.code}: ${intentResult.message}`);
}

const stateResult = normalizeState({
  state: {
    available_budget: 10000,
    account_status: "active",
    prior_transfers_today: 2,
  },
  requiredKeys: ["available_budget", "account_status"],
});

if (!stateResult.ok) {
  throw new Error(`${stateResult.code}: ${stateResult.message}`);
}

const authResult = receiptToAuthorization({
  receipt: verified.receipt,
  intent: intentResult.intent,
  state: stateResult.state,
  issuer: "oxdeai.pdp.local",
  audience: "pep-gateway.local",
  keyId: "main-1",
  ttlSeconds: 30,
});

if (!authResult.ok) {
  throw new Error(`${authResult.code}: ${authResult.message}`);
}

console.log(authResult.authorization);
console.log(authResult.signingPayload);
```

## Build

From repo root:

```bash
pnpm -C packages/sift build
```

## Typecheck

```bash
pnpm -C packages/sift typecheck
```

## Tests

```bash
pnpm -C packages/sift test
```

## Design notes

### Why local verification only?

A runtime dependency on remote receipt verification weakens the execution boundary and introduces availability-dependent trust decisions.

This adapter verifies receipts locally using the supplied Ed25519 public key.

### Why explicit params and explicit state?

OxDeAI authorization is bound to:

```text
(intent, state, policy) → ALLOW | DENY
```

If params or state are guessed, omitted, or defaulted, the authorization loses determinism.

### Why `auth_id = receipt.nonce`?

Replay identity must be explicit and stable.

This adapter maps:

```text
receipt.nonce → AuthorizationV1.auth_id
```

No generated UUIDs. No mutation. No hidden prefixes.

## Related docs

* `../../docs/adapters/sift.md`
* `../../docs/spec/authorization-v1.md`
* `../../docs/spec/pep-gateway-v1.md`
* `../../docs/spec/verification-v1.md`
* `../../docs/spec/canonicalization-v1.md`

## Invariant

```text
No valid AuthorizationV1
→ no execution path
```
