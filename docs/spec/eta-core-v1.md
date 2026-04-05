
# Execution-Time Authorization (ETA) - Core Profile v1

This document defines the minimal normative core of Execution-Time Authorization (ETA) as implemented by OxDeAI.

It is a strict subset of the full OxDeAI protocol specification (`SPEC.md`).
This profile defines the minimal requirements for deterministic, pre-execution authorization and verifiable authorization artifacts.

---

## 1. Purpose

Execution-Time Authorization (ETA) defines a deterministic authorization primitive evaluated before execution:

(intent, state, policy) → decision

Where:

- `decision ∈ { ALLOW, DENY }`

ETA ensures that no external action is executed without prior authorization.

---

## 2. Core Invariant

The following invariant is mandatory:

**No execution path without valid authorization.**

A system is compliant with ETA only if execution is impossible without successful authorization verification.

---

## 3. Scope

This profile defines:

- deterministic decision model
- AuthorizationV1 artifact
- canonicalization rules for signing
- verification requirements (`verifyAuthorization`)
- relying-party enforcement contract

This profile does NOT define:

- delegation
- verification envelopes
- key distribution mechanisms
- orchestration or runtime behavior

---

## 4. Decision Model

The core evaluation function is:

(intent, state, policy) → decision

### Requirements

- Evaluation MUST be deterministic.
- Evaluation MUST be side-effect-free.
- Identical inputs MUST produce identical outputs.
- Evaluation MUST NOT depend on implicit or external mutable context.

### Decision Semantics

- `ALLOW`: execution is permitted if verification succeeds.
- `DENY`: execution MUST NOT occur.

Fail-closed semantics apply:

- Any evaluation failure MUST result in `DENY`.

---

## 5. Authorization Artifact (AuthorizationV1)
`AuthorizationV1` is the core ETA artifact. It MUST contain, at minimum:

- `auth_id` (string, unique)
- `issuer` (string)
- `audience` (string)
- `decision` (`ALLOW` | `DENY`)
- `intent_hash` (hex lowercase SHA-256 of canonicalized intent)
- `issued_at` (unix integer)
- `expiry` (unix integer, > issued_at)
- `alg` (e.g., `ed25519`)
- `kid` (key identifier)
- `signature` (bytes, base64/hex as profiled)

Signing and Verification:

- The signature preimage MUST be the canonical JSON bytes of the AuthorizationV1 object, **excluding the `signature` field**, using the canonicalization rules in `canonicalization-v1.md`.
- Verifiers MUST canonicalize the received authorization (excluding `signature`) identically before signature check.
- Verifiers MUST canonicalize using `canonicalization-v1` and validate signature, audience, expiry, and decision.
- Missing trust config MUST fail closed.

It represents a deterministic authorization decision that can be verified independently.

### Mandatory Fields

An `AuthorizationV1` artifact MUST include:

- `auth_id`
- `issuer`
- `audience`
- `intent_hash`
- `state_hash`
- `policy_id`
- `decision`
- `issued_at`
- `expiry`
- `alg`
- `kid`
- `signature`

### Properties

Authorization artifacts are:

- intent-bound
- state-bound
- policy-bound
- audience-bound
- issuer-bound
- time-bound

### Requirement

An authorization artifact MUST be verified before execution.

---

## 6. Canonicalization

Canonicalization MUST be deterministic and fully specified.

### Requirements

- Object keys MUST be sorted deterministically.
- Encoding MUST be UTF-8.
- No insignificant whitespace.
- Signing MUST NOT depend on language runtime behavior.
- The `signature` field MUST NOT be included in the signed payload.
- The authorization payload used for signing MUST be canonicalized with `canonicalization-v1` and MUST include all AuthorizationV1 fields except the signature bytes/value.

### Signing Input

SIGNING_INPUT = DOMAIN || 0x0A || CANONICAL_PAYLOAD

### Domain Separation

Each artifact type MUST use a distinct domain.

For AuthorizationV1:

OXDEAI_AUTH_V1

---

## 7. Verification (verifyAuthorization)

Verification MUST be performed locally and deterministically.

A verifier MUST:

1. Parse artifact and validate required fields.
2. Reconstruct canonical payload.
3. Reconstruct signing input.
4. Resolve verification key from (`issuer`, `kid`, `alg`).
5. Verify signature.
6. Validate:
   - decision == ALLOW
   - expiry
   - issuer trust
   - audience match
   - intent binding
   - state binding
   - policy binding
7. Ensure `auth_id` has not been consumed.

### Fail-Closed Requirement

Verification MUST fail closed if:

- signature invalid
- trust unresolved
- ambiguity present
- artifact malformed

---

## 8. Relying Party (PEP) Contract

The relying party enforces the execution boundary.

Before execution, it MUST verify:

- authorization validity
- decision == ALLOW
- intent match
- audience match
- non-expired
- non-replayed

### Execution Rule

Execution MUST NOT occur unless verification succeeds.

---

## 9. Security Properties

ETA-compliant systems MUST guarantee:

- determinism
- fail-closed behavior
- non-bypassable enforcement
- verifiable authorization artifacts
- replay resistance (single-use or equivalent mechanism)

---

## 10. Non-Bypassability Requirement

Authorization enforcement MUST be non-bypassable.

It MUST be impossible to execute an action without passing through authorization verification.

SDK-level enforcement alone is insufficient.

---

## 11. Out of Scope

The following are explicitly out of scope:

- delegation (`DelegationV1`)
- verification envelopes
- key distribution protocols
- runtime orchestration
- learning or adaptation systems

These may be defined in extended profiles.

---

## 12. Conformance

An implementation is ETA-conformant if:

- it produces deterministic decisions
- it emits valid AuthorizationV1 artifacts
- it implements canonicalization exactly
- it enforces fail-closed verification
- it enforces the relying-party contract
- it prevents execution without valid authorization

Conformance MUST be verifiable via test vectors.

---
