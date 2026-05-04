# Threat Model

## Scope

This threat model covers the Sift → OxDeAI adapter pipeline as implemented in
this reference repository. It does not cover Sift's internal security, network
transport (assumed TLS in production), or key management infrastructure.

---

## Assets

| Asset | Value |
|-------|-------|
| Execution target | The operation performed by upstream (e.g. financial transfer) |
| AuthorizationV1 signing key | Adapter's Ed25519 private key |
| Internal execution token | Secret shared between PEP and upstream |
| Sift signing key | Used to sign governance receipts |

---

## Threat scenarios

### T-1: Receipt replay

**Threat:** Attacker replays a valid, previously-issued Sift receipt.

**Mitigation:** `auth_id` (= receipt nonce) is consumed atomically on first use.
A second call with the same `auth_id` returns `REPLAY_DETECTED`.

**Residual risk:** If the replay store is not shared across all PEP instances,
a replayed receipt may succeed on a different instance. Replace `MemoryReplayStore`
with a distributed store for multi-instance deployments.

---

### T-2: Intent substitution

**Threat:** Attacker obtains an ALLOW receipt for a low-risk operation (amount=1)
and substitutes high-risk params (amount=1,000,000).

**Mitigation:** `intent_hash` binds the authorization to the specific intent
constructed by the adapter. The PEP recomputes the hash from the intent sent
at execution time and rejects any mismatch.

**Residual risk (KNOWN):** Sift receipts do not include or sign parameter values.
The adapter constructs the intent from caller-supplied params — the PEP cannot
verify that Sift approved those specific params. This is documented in
`docs/adapters/sift.md §"Parameter Binding Guarantee"`. The gap is that the
adapter could (accidentally or maliciously) supply different params than what
Sift evaluated.

---

### T-3: State staleness

**Threat:** Attacker obtains authorization when account is active, then executes
after account is suspended.

**Mitigation:** `state_hash` binds the authorization to the state snapshot at
authorization time. If state changes, the hash sent at execution time will not
match and the PEP rejects with `STATE_HASH_MISMATCH`.

**Residual risk:** The agent controls the state sent to both the adapter (hashed)
and the PEP (verified). A compromised agent could hash state A and send state B.
The PEP's guarantee is: the intent and state at execution time exactly match what
was authorized.

---

### T-4: Authorization forgery

**Threat:** Attacker forges an AuthorizationV1 without the adapter's private key.

**Mitigation:** The PEP verifies the Ed25519 signature before all semantic checks.
A forged authorization without the correct signature is rejected at step 2.

---

### T-5: Direct upstream access

**Threat:** Attacker calls the upstream directly, bypassing the PEP.

**Mitigation:** The upstream rejects every request that does not carry the exact
`X-Internal-Execution-Token`. The token is generated with `randomBytes(32)` and
is only known to the PEP. There is no way to guess it or derive it from the API.

---

### T-6: Audience confusion

**Threat:** Attacker obtains an authorization for PEP-A and presents it to PEP-B.

**Mitigation:** `audience` is part of the signed payload. The PEP rejects
authorizations where `audience` does not match its own configured value.

---

### T-7: Expired authorization use

**Threat:** Attacker delays execution until after the authorization TTL.

**Mitigation:** The PEP checks `expires_at > now`. An expired authorization
returns `EXPIRED` regardless of all other fields being valid.

---

## Out of scope

- Sift service security (assumed trusted; receipt signature is verified)
- TLS / transport security (assumed TLS in production)
- Adapter private key management (use HSM or secrets manager in production)
- Internal token rotation (re-generate on PEP restart; add rotation if needed)
- `MemoryReplayStore` persistence (single-process only; see I-4)
