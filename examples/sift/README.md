# OxDeAI Sift Integration Demo

A runnable end-to-end example that traces the full integration path from a Sift
governance receipt to a PEP execution decision.

> **This is a local simulation for engineering demonstration.  It does not
> connect to any real Sift infrastructure, OxDeAI signing engine, or external
> service.  All keys, receipts, and verifications are generated and performed
> in-process.**

---

## Purpose

The example makes three architectural invariants concrete and observable:

1. **A Sift receipt is not execution authorization.**  It is upstream governance
   input — evidence that a policy engine evaluated a requested action.  Receipt
   verification is a necessary precondition, not a sufficient one.

2. **Execution requires a signed `AuthorizationV1` artifact.**  The artifact is
   constructed locally after verification, intent normalization, and state
   normalization all succeed.  The issuer signs only the fields that were
   verified.

3. **The PEP is the execution boundary.**  The Policy Enforcement Point checks
   audience, expiry, issuer signature, intent binding, state binding, and replay
   before allowing any execution.  Replay protection lives here — not in the
   adapter.

---

## Architecture

```
Mock Sift receipt
       │
       ▼
 verifyReceipt()          ← structural check, version, freshness,
       │                     receipt_hash integrity, Ed25519 signature
       ▼
 normalizeIntent()        ← binds receipt.tool / action to explicit params
       │
       ▼
 normalizeState()         ← validates and normalizes runtime state snapshot
       │
       ▼
 receiptToAuthorization() ← constructs AuthorizationV1 payload +
       │                     signingPayload (hash bindings, time derivation)
       ▼
 sign( signingPayload )   ← demo issuer Ed25519 signature over canonical JSON
       │
       ▼
 pepVerify()              ← execution gate:
                             audience, expiry, signature,
                             intent_hash, state_hash, replay store
```

The Sift key pair and the OxDeAI issuer key pair are distinct.  Verifying a
receipt (with the Sift key) is separate from verifying an authorization (with
the issuer key).

---

## Scenarios

| Scenario | What it shows |
|---|---|
| **ALLOW** | Full happy path — every check passes, `executed: true` |
| **DENY**  | DENY receipt blocked at `verifyReceipt`; adapter and PEP never reached |
| **REPLAY** | Reusing the same `auth_id` from Scenario 1; PEP replay store returns DENY |

---

## Run

```bash
pnpm -C examples/sift start
```

The `start` script builds `packages/sift` first (`prebuild`), compiles this
example, then runs it.  No environment variables or network access required.

Expected output:

```
OxDeAI Sift Integration Demo

Scenario 1 — ALLOW
  receipt verification: OK
  intent normalization: OK
  state normalization: OK
  authorization issued: auth_id=<uuid>
  pep decision: ALLOW
  executed: true

Scenario 2 — DENY
  receipt verification: DENY_DECISION
  executed: false

Scenario 3 — REPLAY
  authorization reused: auth_id=<uuid>
  pep decision: DENY
  reason: REPLAY
  executed: false
```

---

## File layout

```
examples/sift/
  src/
    helpers.ts   — canonical JSON, Ed25519 helpers, mock receipt builder, PEP
    run.ts       — three scenarios and output
  package.json
  tsconfig.json
  README.md
```

### `helpers.ts`

Self-contained implementations of:

- **Canonical JSON** (`canonicalize` + `canonicalBytes` + `canonicalHash`) —
  mirrors the algorithm used internally by `@oxdeai/sift` so hashes computed in
  the PEP match the hashes stored in the authorization.
- **Ed25519 utilities** (`makeKeyPair`, `signCanonical`, `verifyCanonical`).
- **Mock receipt builder** (`buildMockReceipt`) — constructs a structurally
  valid receipt with a correct `receipt_hash` preimage and real Ed25519
  signature.
- **Authorization signer** (`signAuthorization`) — signs the `signingPayload`
  returned by `receiptToAuthorization` and fills `authorization.signature.sig`.
- **PEP simulation** (`pepVerify`) — enforces all execution-boundary checks
  including an in-memory replay store.

### `run.ts`

Orchestrates the three scenarios.  All keys are generated at startup and shared
across scenarios so Scenario 3 can reuse Scenario 1's authorization verbatim.

---

## Preimage reference

The following preimage conventions are critical for signatures and hashes to
verify correctly:

| Field | Preimage |
|---|---|
| `receipt_hash` | `sha256( canonical( receipt MINUS signature AND receipt_hash ) )` |
| Sift `signature` | `sign( canonical( receipt MINUS signature, WITH receipt_hash ) )` |
| Authorization `signature.sig` | `sign( canonical( signingPayload ) )` where `signingPayload` = authorization without `signature.sig` |
| `intent_hash` | `sha256( canonical( OxDeAIIntent ) )` |
| `state_hash` | `sha256( canonical( NormalizedState ) )` |
