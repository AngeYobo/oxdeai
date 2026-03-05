# Verification Envelope

This document describes the OxDeAI verification envelope artifact.

Reference:
- Protocol canonical definition: [protocol.md](./protocol.md)

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
- snapshot integrity
- audit chain integrity
- policy identity consistency

See `protocol.md` for normative validation rules and result semantics (`ok | invalid | inconclusive`).
