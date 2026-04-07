This document is a companion reference (non-normative). Normative definitions are in [../SPEC.md](../SPEC.md) and `docs/spec/`; artifact status (Draft/Stable) is defined there.

# Verification Envelope

`VerificationEnvelopeV1` is pending specification in `docs/spec/`. It is post-execution evidence only and does **not** grant execution authority. All hashes and signature preimages MUST use `canonicalization-v1`.

## Artifact
`VerificationEnvelopeV1`

```json
{
  "formatVersion": 1,
  "snapshot": "<base64>",
  "events": []
}
```

## Verification Intent
The envelope enables stateless third-party verification of:
- snapshot integrity (state commitment)
- audit chain integrity (ordered, hash-linked events)
- policy binding consistency (policyId alignment across snapshot and events)
- decision reproducibility (via deterministic evaluation inputs)

The envelope provides a portable verification surface that allows independent parties to validate
authorization decisions without relying on the original execution environment.

Verification is performed via:

- verifySnapshot()
- verifyAuditEvents()
- verifyEnvelope()

Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; `ok | invalid | inconclusive` are interface-level summaries only. See [`SPEC.md`](../SPEC.md) for normative validation rules and result semantics.
