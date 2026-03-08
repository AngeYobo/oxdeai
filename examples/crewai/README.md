# CrewAI Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

## Run

```bash
pnpm -C examples/crewai start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.
