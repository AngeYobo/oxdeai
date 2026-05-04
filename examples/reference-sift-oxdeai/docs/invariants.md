# Invariants

The following invariants are enforced in code — not documentation, not convention.
Each invariant maps to a specific check in the implementation.

---

## I-1: Non-bypassable execution boundary

**Location:** `apps/upstream/server.ts` — token check on every request.

The upstream refuses any request that does not carry the exact
`X-Internal-Execution-Token` value set at startup. The token is generated
with `randomBytes(32)` and never exposed outside the PEP.

**Audit check:** there is exactly one path to the upstream: through the PEP.
Any direct HTTP call to the upstream returns 403.

---

## I-2: Intent binding

**Location:** `apps/pep-gateway/server.ts` — step 8.

The PEP recomputes `SHA-256(siftCanonical(intent))` from the intent object
supplied in the execution request. If the result does not equal
`authorization.intent_hash`, the request is rejected with `INTENT_HASH_MISMATCH`.

Any modification to `tool`, `params`, or the intent structure produces a
different hash and is blocked.

---

## I-3: State binding

**Location:** `apps/pep-gateway/server.ts` — step 9.

The PEP recomputes `SHA-256(siftCanonical(state))` from the state object
supplied in the execution request. If the result does not equal
`authorization.state_hash`, the request is rejected with `STATE_HASH_MISMATCH`.

If state changes between authorization time and execution time, the check fails.

---

## I-4: Replay protection

**Location:** `apps/pep-gateway/server.ts` — step 10 (last).
**Implementation:** `packages/replay-store/index.ts` — `consumeAuthId`.

`auth_id` is consumed atomically after all other checks pass. A second call
with the same `auth_id` returns `REPLAY_DETECTED` immediately.

The replay check is last to prevent valid auth IDs from being burned by
denial-of-service via a partially-valid request.

---

## I-5: Audience binding

**Location:** `apps/pep-gateway/server.ts` — step 4.

The PEP compares `authorization.audience` against its own configured audience
value. A mismatch returns `AUDIENCE_MISMATCH`.

Audience is part of the signed payload, so changing it invalidates the signature
unless the attacker controls the adapter's private key.

---

## I-6: Expiry enforcement

**Location:** `apps/pep-gateway/server.ts` — step 6.

The PEP checks `authorization.expires_at > floor(Date.now() / 1000)`.
An expired authorization returns `EXPIRED`.

The default TTL is 30 seconds. The adapter accepts a `now` override for testing.

---

## I-7: Signature integrity

**Location:** `apps/pep-gateway/server.ts` — step 2.

The PEP reconstructs the signing payload (AuthorizationV1 minus `signature.sig`)
and verifies the Ed25519 signature using the adapter's public key.

Any field modification (audience, intent_hash, state_hash, expires_at, etc.)
changes the canonical bytes and invalidates the signature.

---

## I-8: Fail-closed everywhere

Every function in this implementation returns a typed error result (`ok: false`)
or throws on unrecoverable conditions. There are no:
- implicit defaults that weaken security checks
- fallback paths that skip verification
- partial-success paths that allow execution with degraded checks

The PEP returns 403 on any error, including unexpected internal errors.
