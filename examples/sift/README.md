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
   precondition for authorization - not execution authorization itself.

2. **OxDeAI is the authorization and enforcement boundary.**  Execution requires
   a signed `AuthorizationV1` artifact.  The artifact is constructed locally
   after verification, intent normalization, and state normalization all succeed.
   The issuer signs only the fields that were verified.

3. **The PEP is the execution gate.**  The Policy Enforcement Point checks
   audience, expiry, issuer signature, intent binding, state binding, and replay
   before allowing any execution.  Replay protection lives here - not in the
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
| Canonical JSON | Python `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)` - keys sorted lexicographically, no whitespace, non-ASCII UTF-16 code units escaped as `\uXXXX` |
| Signatures | Ed25519 over canonical JSON UTF-8 bytes, encoded base64url without padding (RFC 4648 §5) |
| Public keys | Raw 32-byte Ed25519 key material - matches the `x` field of a JWKS entry (RFC 8037 OKP) |

The `ensure_ascii=True` requirement means supplementary characters (U+10000+)
are encoded as two `\uXXXX` escapes (one per UTF-16 surrogate), matching Python
behavior exactly.

---

## Production smoke test (requires provisioning from Sift)

```bash
pnpm -C examples/sift start:prod
```

Runs one live ALLOW smoke path against the real Sift **production**
infrastructure, then re-submits the resulting OxDeAI authorization locally to
assert PEP replay enforcement.

The prod path adds two steps compared to staging:

1. **Challenge fetch** - POST `/api/v1/auth/challenge` -> nonce
2. **Request signing** - agent Ed25519 private key signs the canonical authorize preimage with `params_hash` (covering the nonce, so each request is unique)

Live surfaces contacted:

```
POST https://sift.walkosystems.com/api/v1/auth/challenge
POST https://sift.walkosystems.com/api/v1/authorize
GET  https://sift.walkosystems.com/api/v1/receipt/verify-key
```

### Resolved by the final Sift contract

| Value | Status |
|---|---|
| `tenantId` | `"oxdeai_designpartner"` - confirmed |
| `agentId` | `"oxdeai-boundary-demo-01"` - confirmed |
| `agentRole` | `"validation_agent"` - confirmed |
| Endpoint URLs | `/api/v1/auth/challenge`, `/api/v1/authorize`, `/api/v1/receipt/verify-key` - confirmed |
| Signing preimage fields | `request_id, tenant_id, agent_id, agent_role, action, tool, risk_tier, nonce, timestamp, params_hash` - confirmed |
| Signing canonicalization | sorted keys, no whitespace, `ensure_ascii=FALSE` - confirmed |
| Required header | `X-Sift-Tenant: <tenant_id>` - confirmed |
| params not in preimage | only `params_hash = sha256_hex(sift_canonical(params))` is signed - confirmed |

### Required to execute prod

The Sift production contract is known. To execute the smoke test, provide the
local provisioned agent private key and public key material, then run the prod
script. The private key is used for the custom Ed25519 request signature sent to
Sift and for the local OxDeAI authorization signature used by this smoke test.
The inbound Sift receipt is still verified locally before OxDeAI PEP execution.

### Setting the private key path

Place the private key at:

```
.local/keys/oxdeai-prod-agent-ed25519-private.pem
```

or set the env var:

```bash
SIFT_PROD_PRIVATE_KEY_PATH=/path/to/key.pem pnpm -C examples/sift start:prod
```

The `.local/` directory is already in `.gitignore`.

---

## Production verifier surface (not implemented in demo)

In production, public keys are not bundled with the code.  The runtime follows
this path for each incoming receipt:

1. Read `kid` from the receipt's implicit or explicit key identifier.
2. Check the **KRL (Key Revocation List)** - if `kid` is revoked, reject
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
| **ALLOW** | Full happy path - every check passes, `executed: true` |
| **DENY**  | DENY receipt blocked at `verifyReceipt`; adapter and PEP never reached |
| **REPLAY** | Reusing the same `auth_id` from Scenario 1; PEP replay store returns DENY |

---

## Run

### Local mode (no network required)

```bash
pnpm -C examples/sift start
```

Builds `packages/sift`, compiles the example, runs three fully local
scenarios (ALLOW, DENY, REPLAY) using in-process key generation.  No
environment variables or network access required.

Expected output:

```
OxDeAI Sift Integration Demo

Key material (JWKS x, base64url no-padding):
  sift key  kid=sift-demo-key-1    x=<base64url>
  issuer key kid=demo-issuer-key-1  x=<base64url>

Scenario 1 - ALLOW
  receipt verification: OK
  intent normalization: OK
  state normalization: OK
  authorization issued: auth_id=<uuid>
  pep decision: ALLOW
  executed: true

Scenario 2 - DENY
  receipt verification: DENY_DECISION
  executed: false

Scenario 3 - REPLAY
  authorization reused: auth_id=<uuid>
  pep decision: DENY
  reason: REPLAY
  executed: false
```

### Live production mode (provisioning required)

See **Production smoke test** section below for prerequisites and placeholder
values that must be filled before this command will run.

```bash
pnpm -C examples/sift start:prod
```

### Live staging mode (network required)

```bash
pnpm -C examples/sift start:staging
```

Calls the real Sift staging infrastructure and runs three scenarios:

| Scenario | What is live | What is local |
|---|---|---|
| **1 - LIVE ALLOW** | POST `/api/v1/authorize`; JWKS/KRL fetch; Ed25519 verify | PEP enforcement (`pepVerify`) |
| **2 - LIVE DENY** | POST `/api/v1/authorize`; JWKS/KRL fetch; Ed25519 verify | decision gate (non-ALLOW blocks before PEP) |
| **3a - LIVE REPLAY** | POST `/api/v1/authorize` with REPLAY decision; verify | decision gate |
| **3b - LOCAL REPLAY CHECK** | - | PEP in-memory replay store; ALLOW artifact from Scenario 1 |

Live surfaces contacted:

```
POST https://sift-staging.walkosystems.com/api/v1/authorize
GET  https://sift-staging.walkosystems.com/sift-jwks.json
GET  https://sift-staging.walkosystems.com/sift-krl.json
```

Expected output (when staging is reachable):

```
OxDeAI Sift Live Staging Demo

Scenario 1 - LIVE ALLOW
  authorize call: OK
  local receipt verification: OK
  authorization conversion: OK
  auth_id: staging-<uuid>
  issuer:  sift-staging.walkosystems.com
  policy:  read-only-low-risk
  sift decision: ALLOW
  pep decision: ALLOW
  executed: true

Scenario 3b - LOCAL REPLAY CHECK (OxDeAI PEP)
  (live ALLOW artifact reused - no additional network call)
  authorization reused: auth_id=staging-<uuid>
  pep decision: DENY
  reason: REPLAY
  executed: false

Scenario 2 - LIVE DENY
  authorize call: OK
  local receipt verification: OK
  auth_id: staging-<uuid>
  issuer:  sift-staging.walkosystems.com
  policy:  data-exfil-block
  sift decision: DENY
  pep boundary: not reached - non-ALLOW decision blocks before PEP
  executed: false

Scenario 3a - LIVE REPLAY (Sift-signed REPLAY decision)
  authorize call: OK
  local receipt verification: OK
  auth_id: staging-<uuid>
  issuer:  sift-staging.walkosystems.com
  policy:  replay-window-violation
  sift decision: REPLAY
  pep boundary: not reached - non-ALLOW decision blocks before PEP
  executed: false
```

**CI note:** The `start:staging` command is not run in CI.  It requires
staging network access and depends on external service availability.
The offline staging vector regression suite (`pnpm test` in `packages/sift`)
covers byte-level canonicalization and signature parity without any network
dependency.

---

## File layout

```
examples/sift/
  src/
    helpers.ts        - canonical JSON, Ed25519 helpers, mock receipt builder, PEP
    run.ts            - three local scenarios (no network)
    liveStaging.ts    - staging network I/O helpers
    run-staging.ts    - three live staging scenarios
    liveProd.ts       - prod network I/O helpers (challenge + request signing)
    run-prod.ts       - prod smoke test (live ALLOW plus local replay check)
  package.json
  tsconfig.json
  README.md
```

### `helpers.ts`

Self-contained implementations of:

- **Canonical JSON** (`canonicalize` + `canonicalBytes` + `canonicalHash`) -
  mirrors the Sift contract algorithm (`ensure_ascii=True`) so digests computed
  in the PEP match the digests stored in the authorization.
- **base64url utilities** (`b64uEncode`, `b64uDecode`) - RFC 4648 §5 encoding;
  `b64uDecode` normalizes standard base64 input so both formats decode to
  identical bytes.
- **JWKS key utilities** (`decodeJwksX`) - decodes a JWKS `x` field value
  (base64url) to a raw 32-byte Ed25519 public key.
- **Ed25519 utilities** (`makeKeyPair`, `signCanonical`, `verifyCanonical`) -
  key generation (exports raw key + JWKS x + PKCS8 PEM), signing, and
  verification against raw 32-byte keys.
- **Mock receipt builder** (`buildMockReceipt`) - constructs a structurally
  valid receipt with a correct `receipt_hash` preimage and a real Ed25519
  signature using base64url encoding.
- **Authorization signer** (`signAuthorization`) - signs the `signingPayload`
  returned by `receiptToAuthorization` and fills `authorization.signature.sig`
  with a base64url-no-padding Ed25519 signature.
- **PEP simulation** (`pepVerify`) - enforces all execution-boundary checks
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
