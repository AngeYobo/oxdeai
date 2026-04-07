# Verification

## Status

Non-normative (developer documentation)






Non-normative overview. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status (Draft/Stable) is defined there. All hashes and signature preimages MUST use `canonicalization-v1`. Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; any `ok/invalid/inconclusive` labels are interface summaries only. Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.

OxDeAI exposes stateless verification APIs:
- `verifySnapshot(snapshotBytes)`
- `verifyAuditEvents(events)`
- `verifyEnvelope(envelopeBytes)`

All return `VerificationResult` with status:
- `ok`
- `invalid`
- `inconclusive`

## Snapshot Verification
Checks canonical decode, schema/version, policy binding, and deterministic state-hash recomputation.

## Audit Verification
Checks canonical hash-chain recomputation, timestamp monotonicity, and policy consistency.
Strict mode may return `inconclusive` without state anchors.

## Envelope Verification
Composes snapshot and audit verification and enforces policy consistency between both artifacts.

## Conformance
Use `@oxdeai/conformance` to validate implementations against frozen vectors.
A passing run indicates protocol-aligned behavior for the targeted version.
