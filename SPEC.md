# OxDeAI Specification (v1.2.0)

This document defines the OxDeAI execution authorization protocol.

OxDeAI is a portable, language-agnostic protocol for deterministic pre-execution authorization and post-execution evidence verification in autonomous systems.

The protocol defines:

- portable authorization artifacts
- deterministic policy evaluation requirements
- canonical signing and verification rules
- a relying-party execution contract
- verifiable evidence artifacts

OxDeAI separates authorization decision logic from execution.
A Policy Decision Point (PDP) evaluates whether an action is allowed.
A Policy Enforcement Point (PEP) verifies authorization artifacts and executes the action only if verification succeeds.

The TypeScript implementation in this repository is the reference implementation of this protocol, but conformant implementations MAY exist in any language if they reproduce the same artifacts and verification behavior.

Normative protocol text uses RFC 2119 terms: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY.

## 1. Scope

OxDeAI defines deterministic pre-execution authorization and post-execution evidence verification for autonomous systems.

A conformant implementation MUST produce deterministic outputs for equivalent inputs and MUST enforce the relying-party verification contract before execution occurs.

The protocol defines portable artifacts that can be issued by one system and verified by another, including across language runtimes or infrastructure boundaries.

OxDeAI is protocol-first:

- this repository provides the reference implementation
- other implementations MAY exist in other languages
- conformance is defined by protocol artifacts and verification behavior

Implementations are compliant if they reproduce the protocol artifacts defined in this specification and satisfy the conformance vectors for the targeted version profile.

## 2. Core Artifacts

OxDeAI defines the following first-class protocol artifacts.
These artifacts are language-independent and MUST be interpreted identically across compliant implementations.

- Intent
- CanonicalState snapshot
- AuthorizationV1
- Audit events (hash chained)
- VerificationEnvelopeV1
- VerificationResult
- KeySet

## 3. Determinism Requirements

Determinism is a core protocol invariant.

For identical `(intent, state, policy configuration)` inputs, a conformant implementation MUST produce identical authorization decisions and identical signed artifacts.

Implementations MUST use canonical encoding for signed and hashed payloads.
Verification ordering and violation ordering MUST be deterministic.
Policy-critical logic MUST NOT depend on ambient randomness.

## Multi-Language Implementation Profile

OxDeAI artifacts are language-agnostic protocol artifacts.
Compliant implementations MAY be written in any language.

### Normative Requirements

- Implementations MUST use protocol-defined canonical JSON rules.
- Implementations MUST reconstruct identical signing input bytes for signed artifacts.
- Implementations MUST verify Ed25519 signatures over the canonical payload and domain format defined by this protocol.
- Implementations MUST fail closed on:
  - malformed payloads
  - unsupported algorithms
  - unknown key ids
  - signature mismatch
  - verification ambiguity

### Reference Implementation and Compliance

The TypeScript implementation is the reference implementation.
Other implementations are compliant if they satisfy this specification and pass conformance vectors for the targeted version profile.

### Implementer Checklist

Compliant verifier behavior SHOULD include this sequence:

1. Parse artifact and validate required fields.
2. Canonicalize payload deterministically.
3. Reconstruct signing input bytes exactly.
4. Verify signature and key resolution (`alg`, `kid`, issuer trust context).
5. Validate issuer/audience/policy binding constraints.
6. Validate expiry and decision semantics (`ALLOW` when required).
7. Fail closed on any malformed or ambiguous verification state.

## 4. Authorization Artifact (AuthorizationV1)

`AuthorizationV1` is the primary authorization artifact defined by the OxDeAI protocol.

It represents a deterministic authorization decision issued by a Policy Decision Point (PDP) and verified by a relying party, also referred to as a Policy Enforcement Point (PEP).

`AuthorizationV1` is a portable protocol artifact, not an implementation detail.
It is designed to be verifiable independently of the system that produced it.

### Definition

`AuthorizationV1` is a portable authorization artifact issued by the OxDeAI Policy Decision Point (PDP) to permit a specific action under a specific policy state.
It is consumed by a relying party, also referred to as a Policy Enforcement Point (PEP), and MUST be verified before execution.

`AuthorizationV1` is a first-class protocol artifact. It represents a decision bound to identity, audience, intent, state, policy context, and time.

### Mandatory Fields (v1.2)

An `AuthorizationV1` artifact MUST include all of the following fields:

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

Optional extension fields MAY include:

- `nonce`
- `capability`

Implementations MAY carry additional metadata only if such metadata does not change the semantics of mandatory fields.

### Field Semantics

- `auth_id`: Unique authorization identifier for this artifact instance.
- `issuer`: Identifier of the authorization issuer and trust domain.
- `audience`: Identifier of the relying party for which this authorization is valid.
- `intent_hash`: Canonical hash of the intended action to be executed.
- `state_hash`: Hash of the policy state snapshot against which authorization was granted.
- `policy_id`: Identifier of the policy configuration used for evaluation.
- `decision`: Authorization outcome (`ALLOW` or `DENY`).
- `issued_at`: Issuance time as Unix timestamp (seconds).
- `expiry`: Expiration time as Unix timestamp (seconds).
- `alg`: Signature algorithm identifier.
- `kid`: Key identifier used to select the verification key.
- `signature`: Cryptographic signature over the canonical authorization payload.

### Security Properties

`AuthorizationV1` has the following protocol properties:

- Single-use: `auth_id` MUST be treated as consumable exactly once by the relying party.
- Issuer-bound: validity is scoped to a trusted `issuer`.
- Audience-bound: validity is scoped to the designated `audience`.
- Intent-bound: validity is scoped to the exact `intent_hash`.
- State-bound: validity is scoped to the exact `state_hash`.
- Short-lived: validity is bounded by `issued_at` and `expiry`; expired artifacts are invalid.

These properties are mandatory protocol constraints, not operational recommendations.

### Normative Relying-Party Obligations

Before execution, a relying party MUST verify all of the following:

1. `decision == "ALLOW"`.
2. The authorization has not expired (`expiry` is in the future under verifier time policy).
3. `issuer` is trusted for the current trust context.
4. `audience` matches the current relying-party identity.
5. `intent_hash` matches the exact action about to be executed.
6. `state_hash` binding is respected by the execution context.
7. `policy_id` matches the expected policy context.
8. `auth_id` has not already been consumed.
9. `alg` is supported and permitted by local algorithm policy.
10. `kid` resolves to a trusted verification key for the expected issuer.
11. `signature` validates against the canonical payload and resolved key.

If any verification step fails, execution MUST NOT occur.
If verification state is ambiguous (for example, unresolved trust state, inconsistent key material, or parse ambiguity), verification MUST fail closed.
A reused `auth_id` MUST be rejected.

### Non-Forgeable Verification (v1.2)

Non-forgeable verification ensures that authorization artifacts can be validated independently of the issuing system.

Verification MUST depend only on the artifact contents, canonical payload rules, and trusted verification keys.
No verifier may rely on implicit runtime state or undocumented side channels.

In v1.2, `AuthorizationV1` MUST support public-key verification via `alg`, `kid`, and `signature`.

For signed verification:

- The signature MUST be computed over canonical payload bytes.
- The `signature` field itself MUST NOT be included in the signed payload.
- Different artifact classes MUST use distinct signing domains to prevent cross-artifact signature confusion.
- Unsupported algorithms MUST fail closed.

Verifiers MUST NOT accept unsigned substitutions for artifacts that require signature validation under local policy.

### Compatibility

Older pre-v1.2 authorization paths MAY exist for backward compatibility.
When legacy paths are supported, they SHOULD be explicitly mode-scoped and MUST NOT be confused with public-key verification mode.
Public-key verifiable `AuthorizationV1` is the preferred v1.2 form.

### Minimal Artifact Example

```json
{
  "auth_id": "auth_01JY7K8Z4V3QH6N2M9P0R1S2T3",
  "issuer": "oxdeai.pdp.prod.eu-1",
  "audience": "payments.api.eu-1",
  "intent_hash": "9f3e5c6ad7a4a2f8a2d93f0f31c65a88f95d7dbef4c9f9e30d5f0f6ce7f4a1b2",
  "state_hash": "4e2b7f1a3d8c6e90b5f3a9d7c1e2f4a6b8d0c2e4f6a8b0c1d3e5f7a9b1c3d5e7",
  "policy_id": "policy_prod_payments_v42",
  "decision": "ALLOW",
  "issued_at": 1770001200,
  "expiry": 1770001260,
  "alg": "Ed25519",
  "kid": "2026-01-main",
  "signature": "Wm9NQjN4d0M1N1dXQ0x4eFZ4Qm5hV2xQbUQ3SzdqQ0x0QnI0U2pQeQ=="
}
```

## 5. Non-Forgeable Verification (v1.2)

### 5.1 Algorithm Profile

`Ed25519` is the preferred public-key verification algorithm for v1.2 artifacts.
New v1.2 signed artifacts MUST include `alg`, `kid`, and `signature`.

### 5.2 Signed Payload Rules

The signed payload MUST use canonical encoding.
The `signature` field MUST NOT be included in its own signing payload.
Any mutation of signed fields MUST invalidate signature verification.

### 5.3 Verifier Fail-Closed Requirements

Verifiers MUST fail closed on:

- unknown or unsupported `alg`
- unknown `kid`
- malformed `signature`
- missing required signed fields
- issuer mismatch
- audience mismatch
- policy mismatch when configured
- expiry failure

A verifier MUST NOT accept ambiguous trust state.

### 5.4 Legacy Compatibility Path

Legacy shared-secret artifacts MAY be supported for backward compatibility.
If supported, verifier mode MUST be explicit and documented as legacy.
Public-key verification SHOULD be used for third-party verification.

## 6. Domain Separation

Signatures for different artifact classes MUST use distinct signing domains.
At minimum, implementations MUST support distinct domains:

- `OXDEAI_AUTH_V1`
- `OXDEAI_ENVELOPE_V1`
- `OXDEAI_CHECKPOINT_V1`

A signer MUST compute signature input as:

`domain_separator || canonical_payload_bytes`

Artifact classes MUST NOT share signing domains.
This prevents cross-artifact signature confusion.

## 7. Canonical Signing Format

Canonical signing ensures cross-language interoperability.

All conformant implementations MUST produce identical signing input bytes for identical artifact payloads, regardless of programming language or runtime environment.

### 1. Purpose

OxDeAI requires a deterministic, language-independent canonical signing format for all signed artifacts.
For identical artifact content, compliant implementations MUST produce identical signing input bytes.
Cross-language signature interoperability depends on this property.

### 2. Signed Artifact Classes

The following artifact classes are signed in v1.2:

- `AuthorizationV1`
- `VerificationEnvelopeV1`

Checkpoint artifacts MAY be signed when that profile is enabled.

Each signed artifact class MUST use a distinct signing domain.

### 3. Canonical Payload Rules

Before signing, an artifact payload MUST be converted to the protocol canonical JSON representation.

Canonical payload requirements:

- Object keys MUST be sorted deterministically.
- Source-code field order or runtime object insertion order MUST NOT affect output.
- Insignificant whitespace MUST NOT be included.
- Payload text MUST be UTF-8 encoded.
- Numeric and bigint values MUST use the protocol canonical representation.
- Implementations MUST NOT use language-native object/binary serializers as signing format.
- Implementations MUST NOT sign pretty-printed JSON.
- Implementations MUST NOT sign runtime-dependent binary encodings unless explicitly defined by this protocol.

### 4. Domain Separation

The following domain strings are mandatory:

- `OXDEAI_AUTH_V1`
- `OXDEAI_ENVELOPE_V1`

If checkpoint signing is used, `OXDEAI_CHECKPOINT_V1` MUST be used for that class.

Signatures for different artifact classes MUST use different domain strings.
A verifier MUST reject a signature when the domain does not match the artifact class.
Domain separation prevents cross-artifact signature confusion.

### 5. Signing Input Construction

Signing input bytes are constructed as:

`SIGNING_INPUT = DOMAIN_UTF8 || 0x0A || CANONICAL_PAYLOAD_UTF8`

Where:

- `DOMAIN_UTF8` is the UTF-8 encoding of the domain string.
- `0x0A` is one byte with value newline.
- `CANONICAL_PAYLOAD_UTF8` is the UTF-8 encoding of the canonical JSON payload.

Compliant implementations MUST use exactly this construction.

### 6. Signature Exclusion Rule

The `signature` field MUST NOT be included in the canonical payload that is signed.

All required artifact fields other than `signature` MUST be included in the signed payload.
For v1.2 `AuthorizationV1`, this includes `alg` and `kid`.

Transport-specific metadata not defined by this protocol MUST NOT be included in the signed payload.

### 7. Encoding Requirements

- Canonical payload bytes MUST be UTF-8.
- Signing input bytes MUST be byte-for-byte reproducible across implementations.
- Implementations MUST NOT depend on locale, platform, or runtime defaults.
- Implementations MUST preserve exact protocol field values.

If signatures are represented as base64 or hex for transport, that encoding is a representation layer only and is not part of signing input construction.

### 8. Verification Requirements

A verifier MUST:

1. Determine artifact class and required signing domain.
2. Reconstruct canonical payload using the same canonical JSON rules.
3. Reconstruct signing input using the same domain and separator.
4. Verify signature against that exact byte sequence.

Verification MUST fail if:

- canonical payload cannot be reconstructed deterministically
- required signed fields are missing
- artifact class/domain is unsupported
- reconstructed bytes differ from signer-intended canonical form

### 9. Failure Handling

The following conditions MUST fail closed:

- malformed canonical payload
- unknown artifact type or domain
- unknown or unsupported algorithm
- ambiguous serialization state

Verification ambiguity MUST NOT be treated as success.

### 10. Minimal Example

Example artifact class: `AuthorizationV1`

Domain string:

```text
OXDEAI_AUTH_V1
```

Example canonical JSON payload (excluding `signature`):

```json
{"alg":"Ed25519","audience":"payments.api.eu-1","auth_id":"auth_01JY7K8Z4V3QH6N2M9P0R1S2T3","decision":"ALLOW","expiry":1770001260,"intent_hash":"9f3e5c6ad7a4a2f8a2d93f0f31c65a88f95d7dbef4c9f9e30d5f0f6ce7f4a1b2","issued_at":1770001200,"issuer":"oxdeai.pdp.prod.eu-1","kid":"2026-01-main","policy_id":"policy_prod_payments_v42","state_hash":"4e2b7f1a3d8c6e90b5f3a9d7c1e2f4a6b8d0c2e4f6a8b0c1d3e5f7a9b1c3d5e7"}
```

Conceptual signing input construction:

```text
UTF8("OXDEAI_AUTH_V1") || 0x0A || UTF8(<canonical-json-payload-above>)
```

## 8. Verification Envelope Signing

VerificationEnvelopeV1 MAY carry signature metadata (`issuer`, `alg`, `kid`, `signature`).
If signature metadata is present, verifiers MUST validate it under the same fail-closed rules.
If a verifier runs in signature-required mode, missing envelope signature MUST fail closed.

## 9. Relying Party Contract

A Relying Party, also referred to as a Policy Enforcement Point (PEP), is the system responsible for executing external actions after verifying an authorization artifact.

The relying party enforces the OxDeAI execution authorization boundary.

Before executing any action, the relying party MUST verify the authorization artifact according to the rules defined in this section.

### 1. Definition

A **Relying Party** (Policy Enforcement Point, **PEP**) is the system that receives an authorization artifact and decides whether an external action may execute.
Examples include tool wrappers, compute provisioning services, payment gateways, API execution layers, and orchestration runtimes.

The relying party is the enforcement boundary for OxDeAI authorization decisions.
It MUST enforce this contract before action execution.

### 2. Verification Requirements

Before executing any action, a relying party MUST verify:

1. `decision` equals `ALLOW`.
2. The authorization has not expired.
3. `issuer` is trusted.
4. `audience` matches the current relying party identity.
5. `policy_id` matches the expected policy context.
6. `intent_hash` matches the exact action about to execute.
7. `state_hash` binding is respected by the execution context.
8. `auth_id` has not already been consumed.
9. `alg` is supported by verifier policy.
10. `kid` resolves to a trusted verification key.
11. `signature` is valid for the canonical signed payload.

If any verification step fails, the relying party MUST reject the action.

### 3. Authorization Consumption

`AuthorizationV1` MUST be treated as single-use.

After successful execution, the relying party MUST record `auth_id` as consumed in durable or equivalently reliable replay state.
Any subsequent attempt to reuse the same `auth_id` MUST be rejected.

Single-use consumption is required to prevent replay and reduce time-of-check/time-of-use (TOCTOU) abuse.

### 4. Execution Preconditions

Execution MUST NOT occur unless all of the following are true:

- Authorization verification succeeds.
- Authorization is not expired at decision time.
- Verified `intent_hash` matches the intended action.
- Verified `audience` matches the current relying party.

Authorization MUST be verified immediately before execution.

### 5. Failure Handling

The relying party MUST treat each of the following as authorization failure:

- malformed authorization artifact
- unknown issuer
- unknown `kid`
- unsupported `alg`
- invalid signature
- expired authorization
- reused `auth_id`
- intent mismatch
- audience mismatch

Authorization ambiguity MUST result in denial (fail closed).

### 6. Security Considerations

This contract enforces:

- replay protection via single-use `auth_id`
- intent binding via `intent_hash`
- state binding via `state_hash`
- trust boundaries via `issuer` and `audience`
- forgery resistance via signature verification
- reduced reuse window via short TTL (`issued_at`/`expiry`)

These checks collectively mitigate replay attacks, authorization forgery, and TOCTOU drift between verification and execution.

### 7. Minimal Verification Flow

```text
1. Receive AuthorizationV1 artifact.
2. Resolve verification key from (issuer, kid, alg) and verify signature.
3. Verify issuer trust and audience equality.
4. Verify decision == ALLOW and expiry is in the future.
5. Compute requested action intent hash and compare to intent_hash.
6. Verify policy_id and state_hash bindings for current context.
7. Check auth_id is not consumed.
8. Execute action.
9. Mark auth_id as consumed.
```

## 10. KeySet and Key Rotation Model

The KeySet model provides deterministic resolution of verification keys for authorization artifacts.

This model enables independent verification of OxDeAI artifacts without requiring online access to the issuing system.

### 1. Purpose

OxDeAI signed-artifact verification depends on deterministic resolution of a trusted public key from the tuple:

- `issuer`
- `kid`
- `alg`

The KeySet model defines a deterministic representation of trusted verification keys.
This model is required for non-forgeable verification in v1.2.

### 2. KeySet Definition

A **KeySet** is a structured representation of verification keys for exactly one issuer.

A KeySet object MUST contain:

- `issuer`
- `version`
- `keys`

Field meanings:

- `issuer`: identifier of the entity that issues signed artifacts.
- `version`: version or revision identifier of the KeySet.
- `keys`: collection of verification keys associated with that issuer.

A KeySet MUST correspond to exactly one issuer.
A verifier MUST NOT treat a KeySet as valid for any other issuer.

### 3. Key Entry Definition

Each KeySet key entry MUST contain:

- `kid`
- `alg`
- `public_key`

A key entry MAY also contain:

- `status`
- `not_before`
- `not_after`

Field meanings:

- `kid`: key identifier.
- `alg`: signature algorithm identifier.
- `public_key`: public verification key material.
- `status`: optional lifecycle state (for example, active, retired, revoked).
- `not_before`: optional lower bound on key validity time.
- `not_after`: optional upper bound on key validity time.

Within a KeySet, `kid` MUST be unique.
`alg` MUST identify the verification algorithm unambiguously.
`public_key` MUST be encoded in the format required by the active protocol profile.

### 4. Key Selection Rules

When verifying a signed artifact, a verifier MUST:

1. Identify the artifact `issuer`.
2. Locate a trusted KeySet for that issuer.
3. Select a key entry whose `kid` equals the artifact `kid`.
4. Confirm the key entry `alg` equals the artifact `alg`.
5. Verify the signature using the selected `public_key`.

Verification MUST fail if:

- no trusted KeySet exists for the issuer
- no matching `kid` exists
- `alg` does not match

These conditions are fail-closed requirements.

### 5. Issuer Trust Model

Issuer trust is an external security decision made by the verifier environment.

A verifier MUST trust issuers explicitly.
Untrusted issuers MUST NOT be accepted.
Issuer equality comparison MUST be exact.
A trusted key from one issuer MUST NOT be reused for another issuer.

The core protocol does not require online issuer-trust discovery.
Offline or preconfigured issuer trust is valid in v1.2.

### 6. Key Rotation Rules

Issuers SHOULD support key rotation without unnecessarily invalidating still-valid artifacts.
Multiple active keys MAY exist simultaneously for one issuer.
`kid` MUST distinguish rotated keys.
Newly issued artifacts SHOULD reference the currently active key via `kid`.
Verifiers MUST use the `kid` carried in the artifact and MUST NOT guess a latest key.

Rotation MUST NOT rely on implicit key ordering.

### 7. Validity Windows

Key validity windows are optional key-entry constraints.

- If `not_before` is present, a verifier MUST reject use of that key before that instant.
- If `not_after` is present, a verifier MUST reject use of that key after that instant.
- If windows are absent, the key has no protocol-defined time bound.

Key validity windows are distinct from artifact `expiry`.
Artifact expiry and key validity MUST be evaluated independently.

### 8. Failure Handling

Verification MUST fail closed when:

- issuer is unknown
- `kid` is unknown
- `alg` is unsupported
- key entry is malformed
- key validity windows fail
- multiple ambiguous matching keys exist
- `public_key` cannot be decoded
- trust state is ambiguous

Ambiguity MUST NOT be treated as success.

### 9. Minimal Example

```json
{
  "issuer": "oxdeai.pdp.prod.eu-1",
  "version": "2026-01",
  "keys": [
    {
      "kid": "2026-01-main",
      "alg": "Ed25519",
      "public_key": "MCowBQYDK2VwAyEAq7n1h7vJmV1b8v1z9fP0vQ8sQv1w8mR7Q3v0cV0YQ6k=",
      "not_before": 1767225600,
      "not_after": 1798761600
    }
  ]
}
```

## 11. Replay and TOCTOU Resistance

OxDeAI artifacts are designed to minimize replay and time-of-check/time-of-use (TOCTOU) risks in distributed execution environments.

OxDeAI mitigates replay and check/use drift by combining:

- single-use `auth_id`
- short TTL (`issued_at`/`expiry`)
- intent binding (`intent_hash`)
- state binding (`state_hash`)
- issuer and audience binding

Relying parties MUST enforce single-use state for `auth_id`.
Relying parties SHOULD minimize check-to-execute latency.
If execution context changes after verification, execution SHOULD be re-verified.

## 12. Compatibility and Upgrade Notes

v1.2 adds non-forgeable public-key verification as the preferred path.

Compatibility requirements:

- Implementations MAY support legacy artifacts.
- If legacy mode is supported, verifiers MUST distinguish legacy mode from public-key mode.
- Public-key mode SHOULD be default for third-party verification.
- Future versions MAY strengthen envelope-signing and key-distribution requirements.

## 13. Conformance Requirement

Protocol conformance is determined by artifact compatibility and verification behavior.

An implementation is compliant if it reproduces the protocol artifacts defined in this specification and passes the conformance vectors for the targeted version profile.

A conformant implementation MUST reproduce expected conformance vectors for its targeted profile.
Violation ordering in `VerificationResult` MUST be deterministic.
