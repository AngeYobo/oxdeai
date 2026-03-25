This document is a companion reference.
For the canonical normative specification, see [../SPEC.md](../SPEC.md).

# Verification Envelope

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

See [`SPEC.md`](../SPEC.md) for normative validation rules and result semantics (`ok | invalid | inconclusive`).
