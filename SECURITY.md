# Security Policy and Threat Model (v1.2.0)

This document defines OxDeAI protocol security scope, assumptions, and required failure behavior.

## 1. Security Scope

In scope:

- AuthorizationV1 issuance and verification
- signature verification for signed artifacts
- replay prevention at relying parties
- issuer/audience/policy/intent/state binding checks
- key selection by issuer+kid+alg

Out of scope:

- transport-layer security
- host compromise prevention
- network key-discovery infrastructure

## 2. Threat Model

Primary threats and required mitigations:

- Artifact forgery
  - Mitigation: Ed25519 signatures; trusted public keys; fail-closed verification.
- Replay and authorization reuse
  - Mitigation: single-use `auth_id`; relying-party consumed-id store.
- Signature confusion across artifact types
  - Mitigation: mandatory domain separation (`OXDEAI_AUTH_V1`, `OXDEAI_ENVELOPE_V1`, `OXDEAI_CHECKPOINT_V1`).
- Unknown key / stale key acceptance
  - Mitigation: issuer-scoped keysets; kid lookup; optional validity windows.
- Issuer confusion
  - Mitigation: explicit trusted-issuer policy at verifier.
- Audience confusion
  - Mitigation: mandatory audience match against relying-party identity.
- Tampered envelope
  - Mitigation: canonical payload verification; signature verification when signed.
- Non-monotonic or malformed audit evidence
  - Mitigation: deterministic verifier checks and invalid status.
- State drift between check and use (TOCTOU)
  - Mitigation: state binding + short TTL + immediate enforcement.
- Compromised signing key
  - Mitigation: key rotation, key revocation status, short TTLs, issuer controls.
- Compromised relying party
  - Mitigation: out of protocol control; deployment hardening required.

## 3. Trust Boundaries

- PDP: policy decision point; issues authorizations.
- PEP: policy enforcement point/relying party; verifies before execution.
- Signer: entity controlling private key for `issuer`.
- Verifier: system validating artifacts using trusted keysets.

A relying party MUST NOT trust agent assertions directly.
A relying party MUST trust only valid artifacts under explicitly trusted issuers.

## 4. Cryptographic Model

- Preferred algorithm: `Ed25519`.
- Signed payload: canonical encoding of artifact fields excluding `signature`.
- Signature input: `domain_separator || canonical_payload_bytes`.
- Verification is fail-closed.

Requirements:

- custom cryptography MUST NOT be used
- unsupported algorithms MUST fail closed
- ambiguous algorithm handling MUST NOT be permitted

Legacy HMAC verification MAY be supported as explicit compatibility mode.

## 5. Key Management Guidance

- Private signing keys SHOULD be stored in HSM/KMS or equivalent secure custody.
- Private keys MUST NOT be embedded in client applications.
- Issuer identity SHOULD be stable and unique per trust domain.
- `kid` SHOULD be rotated with overlap periods for verifier rollout.
- Keysets SHOULD support multiple active keys during rotation.
- Compromise recovery SHOULD include key revocation, kid retirement, and signer replacement.
- v1.2 key distribution MAY be local/offline; network discovery is optional and external to core protocol.

## 6. Replay and TOCTOU Mitigations

Relying parties MUST enforce:

- single-use `auth_id`
- strict `expiry` checks
- intent binding (`intent_hash`)
- state binding (`state_hash`)
- issuer and audience binding

Relying parties SHOULD execute immediately after successful verification.
If the execution context changes materially, verification SHOULD be repeated.

## 7. Verification Failure Policy

Verification failures MUST block execution.

Fail-closed conditions include:

- malformed artifacts
- unknown `alg`
- unknown `kid`
- missing required fields
- invalid signature
- issuer mismatch
- audience mismatch
- policy mismatch when expected
- expired authorization
- replayed `auth_id`

Implementations MUST NOT downgrade invalid artifacts to warnings for execution gating.

## 8. Vulnerability Reporting

## 8. Test Fixture Key Material

Production private keys MUST NOT be committed.

Cryptographic test fixtures are permitted only in explicit fixture paths and MUST be labeled:

- `TEST ONLY`
- `DO NOT USE IN PRODUCTION`

Deterministic fixtures SHOULD be minimized.
Where deterministic fixtures are not required, tests SHOULD generate ephemeral keypairs at runtime.

Repository scanners and reviewers SHOULD treat fixture-path key material as test scope only, while continuing strict detection for all non-fixture paths.

## 9. Vulnerability Reporting

Report vulnerabilities privately to:

security@oxdeai.io

Do not disclose publicly before coordinated disclosure.
