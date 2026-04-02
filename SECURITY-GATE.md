# Security Gate

This repo enforces a fail-closed vulnerability gate in CI.

## Policy format

`security/vuln-policy.json`
```json
{
  "exceptions": [
    {
      "id": "GHSA-xxxx",
      "package": "pkg-name",
      "severity": "medium",
      "reason": "why this is temporarily accepted",
      "expires_on": "2026-06-30"
    }
  ]
}
```

Rules:
- Every exception must include `reason`, `severity`, and `expires_on` (ISO date).
- Expired exceptions fail the gate.
- High / critical always fail.
- Medium fails unless a non-expired exception matches.

## Adding a temporary exception
1) Add an entry to `security/vuln-policy.json` with id/package/severity, a short reason, and a near-term `expires_on`.
2) Commit the change and re-run the gate.
3) Remove exceptions once fixed.

## How it runs
- CI runs `pnpm audit --json > audit.json || true`
- Then `node scripts/security-gate.mjs audit.json security/vuln-policy.json`
- Gate prints blocking findings, matched/expired exceptions, and pass/fail.
