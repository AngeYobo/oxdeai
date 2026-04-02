# Security Gate Decision Artifact

Minimal, deterministic proof of the security authorization gate decision. This is not an OxDeAI runtime authorization artifact; it is a lightweight integrity record for the pre-merge vulnerability gate.

## Format
```json
{
  "formatVersion": 1,
  "type": "SecurityGateDecision",
  "decision": "ALLOW",
  "reason": "no blocking findings",
  "timestamp": "2026-04-02T10:00:00.000Z",
  "policyHash": "...",
  "exceptionsHash": "...",
  "findingsHash": "...",
  "inputHash": "...",
  "artifactHash": "..."
}
```

Hashes are SHA-256 over a canonical (sorted-key) JSON representation:
- `policyHash`: hash of `policy.rules`
- `exceptionsHash`: hash of `exceptions`
- `findingsHash`: hash of normalized findings
- `inputHash`: hash of `{ policyHash, exceptionsHash, findingsHash, decision, reason }`
- `artifactHash`: hash of the artifact object without the `artifactHash` field

## What it proves
- The decision (ALLOW/DENY) for a specific set of inputs.
- Integrity of the inputs used: policy rules, exceptions, findings.
- Deterministic reproduction: identical logical inputs produce identical hashes.

## What it does NOT prove
- No cryptographic signature or key-based trust model.
- No guarantee of who produced the artifact.
- Not an OxDeAI runtime authorization artifact.

## Generate
```
node scripts/security-gate.mjs audit.json security/vuln-policy.json --artifact-out=security-gate-decision.json
```

## Verify
```
node scripts/verify-security-gate-artifact.mjs security-gate-decision.json
```

Expected output: PASS/FAIL with computed vs stored hash. If the hash matches, the artifact is intact for the given content.
