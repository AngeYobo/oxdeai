# Security Authorization Gate

Repo-level pre-merge security gate (non-normative). Protocol definitions live in `SPEC.md` and `docs/spec/`; this gate enforces repository policy, not OxDeAI protocol artifacts.

Deterministic pre-merge authorization: audit intent + state + policy -> ALLOW / DENY.

## Core invariant

No valid exception -> no merge path.

This gate is intentionally fail-closed.

High and critical findings always block. Moderate findings block unless covered by a valid, non-expired exception.
High and critical severities are always denied, regardless of policy rules.

## Policy-as-code

`security/vuln-policy.json`
```json
{
  "rules": {
    "critical": "deny",
    "high": "deny",
    "moderate": "require_exception",
    "low": "warn"
  },
  "exceptions": [
    {
      "id": "GHSA-xxxx",
      "package": "pkg-name",
      "severity": "moderate",
      "reason": "why this is temporarily accepted",
      "expires_on": "2026-06-30"
    }
  ]
}
```

Semantics:
- intent: merge this repo state
- state: audit findings + exception state + current date
- policy: severity rules + exception requirements
- decision: ALLOW / DENY

Rules:
- Every exception must include `reason`, `severity`, and `expires_on` (ISO date).
- Expired exceptions fail the gate.
- Critical/high: deny.
- Moderate: require a valid, non-expired exception.
- Low: warn (does not block).

## Adding a temporary exception
1) Add to `security/vuln-policy.json` with id/package/severity, a short reason, and a near-term `expires_on`.
2) Commit the change and re-run the gate.
3) Remove exceptions once fixed.

## How it runs
- CI runs `pnpm audit --json > audit.json || true`
- Then `node scripts/security-gate.mjs audit.json security/vuln-policy.json`
- Gate prints blocking findings, matched/expired exceptions, warnings, and the final decision (ALLOW / DENY).
