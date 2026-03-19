# DelegationV1 Specification

**Status:** Draft
**Version:** v2.x candidate
**Depends on:** OxDeAI Specification v1.2+, AuthorizationV1

---

## 1. Overview

`DelegationV1` is a protocol artifact that allows a principal holding a valid `AuthorizationV1` to delegate a strictly narrowed subset of that authorization to a second principal (the delegatee).

The delegatee may present `DelegationV1` to a Policy Enforcement Point (PEP) as a substitute authorization credential, subject to scope and expiry constraints that are at most as permissive as the parent `AuthorizationV1`.

Key properties:

- **Derived** - must reference a valid parent `AuthorizationV1`
- **Strictly narrowing** - scope may only be equal to or more restrictive than the parent
- **Single-hop** - no re-delegation; a `DelegationV1` cannot itself be delegated
- **Locally verifiable** - no control plane required at verification time
- **Signed** - Ed25519, same signing model as `AuthorizationV1`
- **Fail-closed** - any verification ambiguity MUST result in DENY

---

## 2. JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12",
  "$id": "https://oxdeai.dev/schemas/delegation-v1.json",
  "title": "DelegationV1",
  "type": "object",
  "required": [
    "delegation_id",
    "issuer",
    "delegator",
    "delegatee",
    "parent_auth_hash",
    "scope",
    "policy_id",
    "issued_at",
    "expiry",
    "alg",
    "kid",
    "signature"
  ],
  "additionalProperties": false,
  "properties": {
    "delegation_id": {
      "type": "string",
      "description": "Unique identifier for this delegation artifact. MUST be globally unique. Recommended: UUID v4."
    },
    "issuer": {
      "type": "string",
      "description": "Identity of the system that produced this artifact (e.g. agent runtime ID)."
    },
    "delegator": {
      "type": "string",
      "description": "Identity of the principal delegating authority. MUST match the audience of the parent AuthorizationV1."
    },
    "delegatee": {
      "type": "string",
      "description": "Identity of the principal receiving delegated authority."
    },
    "parent_auth_hash": {
      "type": "string",
      "description": "SHA-256 hex digest of the canonical encoding of the parent AuthorizationV1. Binds this delegation to a specific parent artifact."
    },
    "scope": {
      "type": "object",
      "description": "Delegated scope. All fields MUST be equal to or more restrictive than the parent AuthorizationV1 scope.",
      "additionalProperties": false,
      "properties": {
        "tools": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Allowlisted tool names. MUST be a subset of the parent authorization's allowed tools. Omit to inherit parent tools unchanged."
        },
        "max_amount": {
          "type": "number",
          "description": "Maximum spend per action. MUST be ≤ parent authorization amount."
        },
        "max_actions": {
          "type": "integer",
          "description": "Maximum number of actions authorized under this delegation."
        },
        "max_depth": {
          "type": "integer",
          "description": "Maximum agent recursion depth permitted under this delegation. MUST be ≤ parent value if parent defines one."
        }
      }
    },
    "policy_id": {
      "type": "string",
      "description": "Policy identity. MUST match the policy_id of the parent AuthorizationV1."
    },
    "issued_at": {
      "type": "integer",
      "description": "Unix timestamp (ms) at which this delegation was issued."
    },
    "expiry": {
      "type": "integer",
      "description": "Unix timestamp (ms) at which this delegation expires. MUST be ≤ parent AuthorizationV1 expiry."
    },
    "alg": {
      "type": "string",
      "enum": ["EdDSA"],
      "description": "Signing algorithm. Only EdDSA (Ed25519) is supported."
    },
    "kid": {
      "type": "string",
      "description": "Key ID used to sign this artifact. MUST resolve in the issuer's KeySet."
    },
    "signature": {
      "type": "string",
      "description": "Base64url-encoded Ed25519 signature over the canonical signing input."
    }
  }
}
```

---

## 3. Canonical Signing Input

The signature MUST be computed over the following canonical input, using the same domain-separated format as `AuthorizationV1`:

```
oxdeai:delegation:v1:<canonical_json>
```

Where `<canonical_json>` is the deterministic JSON encoding of the `DelegationV1` object **excluding** the `signature` field, with:

- keys sorted lexicographically at every nesting level
- no insignificant whitespace
- no `undefined` or `null` values for optional absent fields (omit the key entirely)

Implementations MUST produce identical byte sequences for identical inputs.

---

## 4. Invariants

### 4.1 Scope Narrowing

A `DelegationV1` MUST NOT expand authority relative to the parent `AuthorizationV1`.

| Field | Rule |
|---|---|
| `scope.tools` | MUST be a subset of parent allowed tools (or omitted to inherit) |
| `scope.max_amount` | MUST be ≤ parent `amount` |
| `scope.max_actions` | No equivalent parent field; MAY be set freely |
| `scope.max_depth` | MUST be ≤ parent `max_depth` if parent defines one |
| `policy_id` | MUST equal parent `policy_id` |
| `expiry` | MUST be ≤ parent `expiry` |

Violation of any narrowing rule MUST result in DENY. Verification MUST NOT proceed past the first narrowing failure.

### 4.2 Delegator Binding

The `delegator` field MUST exactly match the `audience` field of the parent `AuthorizationV1`.

If the parent has no `audience`, verification MUST fail closed (DENY).

### 4.3 Expiry

`expiry` MUST be:
- a valid integer timestamp in milliseconds
- strictly greater than `issued_at`
- less than or equal to parent `AuthorizationV1` expiry

### 4.4 Single-Hop Enforcement

A `DelegationV1` artifact MUST NOT be used as the parent of another `DelegationV1`. The PEP MUST reject any chain where the parent artifact is itself a delegation.

### 4.5 Replay Protection

`delegation_id` is the replay nonce. Implementations that track consumed delegation IDs MUST reject a `DelegationV1` whose `delegation_id` has been previously seen in the same policy scope.

Implementations that do not track consumed IDs MUST document this as a deployment assumption. Fail-closed behavior is REQUIRED if replay state is ambiguous.

### 4.6 Fail-Closed Conditions

Verification MUST return DENY if any of the following are true:

- signature is invalid or unverifiable
- `kid` does not resolve in the issuer's KeySet
- parent `AuthorizationV1` cannot be resolved or its hash does not match `parent_auth_hash`
- parent `AuthorizationV1` is itself expired
- any scope narrowing invariant is violated
- `delegator` does not match parent `audience`
- `policy_id` does not match parent `policy_id`
- `expiry` has passed at verification time
- `delegation_id` has been previously consumed (if replay tracking is active)
- the artifact is structurally malformed

---

## 5. Verification Algorithm

Inputs:
- `delegation`: the `DelegationV1` artifact to verify
- `parent_auth`: the resolved `AuthorizationV1` referenced by `parent_auth_hash`
- `keyset`: the issuer's `KeySet`
- `now`: current timestamp in ms (injected, not ambient)
- `consumed_ids`: optional set of previously seen delegation IDs

Returns: `ALLOW` or `DENY` with a reason list.

```
function verifyDelegation(delegation, parent_auth, keyset, now, consumed_ids?):

  // Step 1: Structural validation
  if delegation is missing required fields:
    return DENY("malformed artifact")

  // Step 2: Signature verification
  key = keyset.resolve(delegation.kid)
  if key is null:
    return DENY("unknown kid")

  signing_input = "oxdeai:delegation:v1:" + canonicalJson(delegation without signature)
  if not Ed25519.verify(key, signing_input, delegation.signature):
    return DENY("invalid signature")

  // Step 3: Resolve and bind parent authorization
  computed_hash = SHA256(canonicalJson(parent_auth))
  if computed_hash != delegation.parent_auth_hash:
    return DENY("parent_auth_hash mismatch")

  // Step 4: Validate parent is a raw AuthorizationV1 (not a DelegationV1)
  if parent_auth.type == "DelegationV1":
    return DENY("multi-hop delegation not permitted")

  // Step 5: Validate parent expiry
  if parent_auth.expiry < now:
    return DENY("parent authorization expired")

  // Step 6: Validate delegator binding
  if delegation.delegator != parent_auth.audience:
    return DENY("delegator does not match parent audience")

  // Step 7: Validate policy binding
  if delegation.policy_id != parent_auth.policy_id:
    return DENY("policy_id mismatch")

  // Step 8: Validate delegation expiry
  if delegation.expiry > parent_auth.expiry:
    return DENY("expiry exceeds parent expiry")
  if delegation.expiry < delegation.issued_at:
    return DENY("expiry before issued_at")
  if delegation.expiry < now:
    return DENY("delegation expired")

  // Step 9: Validate scope narrowing
  if delegation.scope.max_amount is set AND delegation.scope.max_amount > parent_auth.amount:
    return DENY("max_amount exceeds parent amount")

  if delegation.scope.tools is set:
    if not delegation.scope.tools ⊆ parent_auth.allowed_tools:
      return DENY("tool scope exceeds parent allowed tools")

  if delegation.scope.max_depth is set AND parent_auth.max_depth is set:
    if delegation.scope.max_depth > parent_auth.max_depth:
      return DENY("max_depth exceeds parent max_depth")

  // Step 10: Replay check
  if consumed_ids is provided AND delegation.delegation_id in consumed_ids:
    return DENY("delegation_id already consumed")

  return ALLOW
```

---

## 6. PEP Contract

A PEP that accepts `DelegationV1` as an authorization credential MUST:

1. Resolve the parent `AuthorizationV1` locally (from cache or request context - no live control plane call)
2. Run the full verification algorithm above
3. Execute the action only if verification returns `ALLOW`
4. Record a delegation audit event referencing both `delegation_id` and `parent_auth_hash`
5. Mark `delegation_id` as consumed if replay tracking is active

A PEP MUST NOT:

- execute on a `DelegationV1` that has not passed full verification
- accept a `DelegationV1` whose parent cannot be resolved
- accept a scope claim without comparing against the resolved parent

---

## 7. Audit Event

On `ALLOW`, the PEP MUST emit an audit event of the form:

```json
{
  "type": "DELEGATION_EXECUTION",
  "delegation_id": "<delegation_id>",
  "parent_auth_hash": "<parent_auth_hash>",
  "delegatee": "<delegatee>",
  "policy_id": "<policy_id>",
  "timestamp": "<unix ms>",
  "decision": "ALLOW"
}
```

On `DENY`, the PEP MUST emit:

```json
{
  "type": "DELEGATION_DENIED",
  "delegation_id": "<delegation_id or null>",
  "reason": "<reason string>",
  "timestamp": "<unix ms>",
  "decision": "DENY"
}
```

Both events MUST be included in the hash-chained audit log.

---

## 8. What Is Explicitly Out of Scope

| Feature | Status |
|---|---|
| Multi-hop delegation chains | Not supported (single hop only) |
| Revocation system | Not included (stateless model) |
| Federation across trust domains | Not included |
| Dynamic scope expansion | Prohibited by invariant |
| Delegation of delegation | Prohibited by §4.4 |

---

## 9. Relationship to AuthorizationV1

| Property | AuthorizationV1 | DelegationV1 |
|---|---|---|
| Issued by | PDP | Delegating principal |
| Verified by | PEP | PEP |
| Depends on | policy state | parent AuthorizationV1 |
| Scope | defined by policy | subset of parent |
| Re-issuable | no | no |
| Multi-hop | n/a | prohibited |
| Signing | Ed25519 | Ed25519 |

---

## 10. References

- [OxDeAI Specification](../../SPEC.md)
- [AuthorizationV1 schema](../../SPEC.md#4-authorizationv1)
- [KeySet Distribution](../../SPEC.md#11-keyset-distribution-v1-baseline)
- [Cross-Organization Verification Model](../../SPEC.md#12-cross-organization-verification-model)
- [Roadmap: v2.x Delegated Agent Authorization](../../ROADMAP.md)
