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

1. **Sift is the decision layer.**  A receipt is evidence that a Sift policy
   engine evaluated a requested action.  Receipt verification is a necessary
   precondition for authorization — not execution authorization itself.

2. **OxDeAI is the authorization and enforcement boundary.**  Execution requires
   a signed `AuthorizationV1` artifact.  The artifact is constructed locally
   after verification, intent normalization, and state normalization all succeed.
   The issuer signs only the fields that were verified.

3. **The PEP is the execution gate.**  The Policy Enforcement Point checks
   audience, expiry, issuer signature, intent binding, state binding, and replay
   before allowing any execution.  Replay protection lives here — not in the
   adapter.

---

## Architecture

```
Mock Sift receipt
       │
       ▼
 verifyReceipt()          ← struct, version, receipt_hash integrity,
       │                     Ed25519 signature, decision, freshness
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
 sign( signingPayload )   ← demo issuer Ed25519 signature over Sift-canonical JSON
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

## Wire format

The Sift staging verifier uses a specific canonicalization and encoding contract.
`helpers.ts` and `@oxdeai/sift` implement the same contract so digests and
signatures computed locally match what the Sift service produces.

| Surface | Format |
|---|---|
| Canonical JSON | Python `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)` — keys sorted lexicographically, no whitespace, non-ASCII UTF-16 code units escaped as `\uXXXX` |
| Signatures | Ed25519 over canonical JSON UTF-8 bytes, encoded base64url without padding (RFC 4648 §5) |
| Public keys | Raw 32-byte Ed25519 key material — matches the `x` field of a JWKS entry (RFC 8037 OKP) |

The `ensure_ascii=True` requirement means supplementary characters (U+10000+)
are encoded as two `\uXXXX` escapes (one per UTF-16 surrogate), matching Python
behavior exactly.

---

## Production verifier surface (not implemented in demo)

In production, public keys are not bundled with the code.  The runtime follows
this path for each incoming receipt:

1. Read `kid` from the receipt's implicit or explicit key identifier.
2. Check the **KRL (Key Revocation List)** — if `kid` is revoked, reject
   immediately before any signature work.
3. Look up the JWKS entry whose `kid` matches.  If not found, trigger a JWKS
   refresh (cache may be stale) and retry once.
4. Decode the `x` field (base64url → raw 32 bytes) and verify the signature.

JWKS entry shape (RFC 8037 OKP):

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "alg": "EdDSA",
  "use": "sig",
  "kid": "<key-id>",
  "x": "<base64url-raw-32-byte-key>"
}
```

The `alg: "EdDSA"` field is JWKS metadata.  The runtime artifact uses
`alg: "ed25519"` (lowercase) as the Sift contract literal in
`AuthorizationV1Payload.signature.alg`.

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

Key material (JWKS x, base64url no-padding):
  sift key  kid=sift-demo-key-1    x=<base64url>
  issuer key kid=demo-issuer-key-1  x=<base64url>

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
  mirrors the Sift contract algorithm (`ensure_ascii=True`) so digests computed
  in the PEP match the digests stored in the authorization.
- **base64url utilities** (`b64uEncode`, `b64uDecode`) — RFC 4648 §5 encoding;
  `b64uDecode` normalizes standard base64 input so both formats decode to
  identical bytes.
- **JWKS key utilities** (`decodeJwksX`) — decodes a JWKS `x` field value
  (base64url) to a raw 32-byte Ed25519 public key.
- **Ed25519 utilities** (`makeKeyPair`, `signCanonical`, `verifyCanonical`) —
  key generation (exports raw key + JWKS x + PKCS8 PEM), signing, and
  verification against raw 32-byte keys.
- **Mock receipt builder** (`buildMockReceipt`) — constructs a structurally
  valid receipt with a correct `receipt_hash` preimage and a real Ed25519
  signature using base64url encoding.
- **Authorization signer** (`signAuthorization`) — signs the `signingPayload`
  returned by `receiptToAuthorization` and fills `authorization.signature.sig`
  with a base64url-no-padding Ed25519 signature.
- **PEP simulation** (`pepVerify`) — enforces all execution-boundary checks
  including audience, expiry, Ed25519 signature (over Sift-canonical JSON),
  intent_hash, state_hash, and an in-memory replay store.  Takes
  `issuerPublicKeyRaw` (raw 32-byte key, JWKS `x` format).

### `run.ts`

Orchestrates the three scenarios.  All keys are generated at startup and shared
across scenarios so Scenario 3 can reuse Scenario 1's authorization verbatim.
Prints key material in JWKS `x` format at startup so the wire format is
observable.

---

## Preimage reference

The following preimage conventions are critical for signatures and hashes to
verify correctly.  All canonical JSON uses `ensure_ascii=True`; all signatures
are base64url without padding.

| Field | Preimage |
|---|---|
| `receipt_hash` | `sha256( sift_canonical( receipt MINUS signature AND receipt_hash ) )` |
| Sift `signature` | `sign( sift_canonical( receipt MINUS signature, WITH receipt_hash ) )` → base64url |
| Authorization `signature.sig` | `sign( sift_canonical( signingPayload ) )` → base64url; `signingPayload` = authorization without `signature.sig` (`signature.alg` and `signature.kid` present) |
| `intent_hash` | `sha256( sift_canonical( OxDeAIIntent ) )` |
| `state_hash` | `sha256( sift_canonical( NormalizedState ) )` |
