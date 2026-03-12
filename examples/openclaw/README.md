# OpenClaw Integration Demo

OpenClaw-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

## Run

```bash
pnpm -C examples/openclaw start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.

See the canonical shared scenario: [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).
