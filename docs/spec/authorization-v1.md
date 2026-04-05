# OxDeAI AuthorizationV1 Specification

**Version:** v1
**Status:** Draft (Normative Artifact Specification)

---

## 1. Purpose

`AuthorizationV1` is the canonical OxDeAI authorization artifact.

It represents a deterministic authorization decision produced by evaluating:

```text
(intent, state, policy) → ALLOW | DENY
```

Only `ALLOW` artifacts are valid for execution.

> If no valid `AuthorizationV1` is present, execution **MUST NOT** occur.

---

## 2. Relationship to ETA Core

* **ETA Core** defines the decision function
* **AuthorizationV1** defines the portable, verifiable output

This specification defines the artifact **independently of any implementation**.

---

## 3. Canonicalization Dependency

All hashing and signing **MUST** use:

→ `canonicalization-v1.md`

### Requirements

* `intent_hash` **MUST** be computed from canonicalized intent bytes
* `state_hash` **MUST** be computed from canonicalized state bytes
* The signed payload **MUST** be canonicalized before signing

### Failure rule

> If canonicalization fails:
>
> * Authorization **MUST** be considered invalid
> * Execution **MUST** fail closed

---

## 4. Schema

An `AuthorizationV1` artifact **MUST** conform to:

```json
{
  "version": "AuthorizationV1",
  "auth_id": "string",
  "issuer": "string",
  "audience": "string",
  "decision": "ALLOW",
  "intent_hash": "lowercase hex sha256",
  "state_hash": "lowercase hex sha256",
  "policy_version": "string",
  "issued_at": 1712448000,
  "expires_at": 1712448060,
  "signature": {
    "alg": "Ed25519",
    "kid": "string",
    "sig": "string"
  }
}
```

---

## 5. Field Definitions

### version

* **MUST** equal `"AuthorizationV1"`

---

### auth_id

* Unique identifier for the authorization
* **MUST** be treated as single-use
* Replay **MUST** be rejected

---

### issuer

* Identifies the issuing authority
* **MUST** be verified against trusted key sets

---

### audience

* Identifies the intended verifier / PEP
* **MUST** match the execution boundary

---

### decision

* **MUST** be `"ALLOW"` for execution
* Any other value **MUST** be rejected

---

### intent_hash

* SHA-256 over canonicalized intent
* **MUST** exactly match the requested action

---

### state_hash

* SHA-256 over canonicalized state snapshot
* Binds the decision to evaluation state

---

### policy_version

* Identifies the policy used during evaluation

---

### issued_at

* Unix timestamp (seconds)

---

### expires_at

* Unix timestamp (seconds)
* **MUST** be strictly enforced

---

### signature.alg

* **MUST** be `"Ed25519"`

---

### signature.kid

* Key identifier used for verification

---

### signature.sig

* Signature over canonicalized payload

---

## 6. Signature Preimage (Normative)

The signature **MUST** be computed over:

```text
canonicalize(AuthorizationV1_without_signature.sig)
```

### Rules

* The entire AuthorizationV1 object **MUST** be included in the preimage, except `signature.sig`.
* `signature.alg` and `signature.kid` **MUST** be included.
* The canonicalization rules in `canonicalization-v1.md` **MUST** be used for this preimage.

Canonicalization **MUST** follow `canonicalization-v1.md`.

---

## 7. Hash Requirements

Implementations **MUST**:

* Use SHA-256
* Encode hashes as lowercase hexadecimal
* Reject mismatches deterministically

---

## 8. Signature Requirements

Verification **MUST**:

* Use Ed25519
* Resolve `kid` to a trusted public key
* Verify signature over canonical payload

> Any failure **MUST** result in denial.

---

## 9. Trust Model

> Signature validity ≠ trust

An authorization is valid **only if all conditions hold**:

* Signature verifies
* Issuer is trusted
* `kid` resolves in trusted key sets
* Audience matches verifier
* Artifact is not expired
* `auth_id` has not been replayed
* `intent_hash` matches the action

### Failure rule

```text
Any condition fails → reject
```

### Strict mode

* Missing trust configuration **MUST** fail closed

---

## 10. Verification Procedure

A conforming verifier **MUST**:

1. Parse artifact
2. Validate schema
3. Canonicalize signed payload
4. Verify signature
5. Resolve trusted key
6. Validate issuer trust
7. Validate audience
8. Check expiration
9. Recompute `intent_hash`
10. Compare hashes
11. Check replay (`auth_id`)
12. Reject ambiguity

### Failure rule

> If any step fails → execution **MUST NOT** occur

---

## 11. Replay Protection

* `auth_id` **MUST** be single-use

If reused:

* **MUST** return denial
* **MUST NOT** execute

Replay protection is **mandatory**.

---

## 12. Failure Semantics

Verification **MUST** fail closed.

### Includes

* Malformed artifact
* Missing fields
* Canonicalization failure
* Hash mismatch
* Signature failure
* Trust failure
* Audience mismatch
* Expiration
* Replay

> No fallback or partial execution is allowed.

---

## 13. Example

```json
{
  "version": "AuthorizationV1",
  "auth_id": "auth_01",
  "issuer": "oxdeai.pdp.local",
  "audience": "pep-gateway.local",
  "decision": "ALLOW",
  "intent_hash": "b75c8d1d9952254b2386f4e412f8fd0b8ac7361ddb54e50c22b19ffc1a3c8c2d",
  "state_hash": "4e5d7f3b1c2a99887766554433221100aabbccddeeff00112233445566778899",
  "policy_version": "policy.v1",
  "issued_at": 1712448000,
  "expires_at": 1712448060,
  "signature": {
    "alg": "Ed25519",
    "kid": "main-1",
    "sig": "BASE64_OR_HEX_SIGNATURE"
  }
}
```

---

## 14. Invariant

```text
No valid AuthorizationV1
→ no verified authorization
→ no execution path
```

---

## Remarques critiques (alignement avec ton patch)

### Ce qui est maintenant correct

* séparation claire **artifact vs ETA Core**
* dépendance explicite à canonicalization
* modèle de vérification déterministe
* fail-closed systématique
* signature préimage bien définie

### Ce que tu pourrais renforcer (prochaine itération)

1. **Types exacts**

   * définir format de `auth_id` (UUID ? string opaque ?)
   * définir encodage `signature.sig` (base64 vs hex)

2. **Time semantics**

   * tolérance clock skew (sinon edge failures en prod)

3. **Audience matching**

   * exact match vs prefix vs set

4. **State binding mode**

   * optional vs required selon profile (important pour Gateway spec)
