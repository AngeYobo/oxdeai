# AutoGen Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

## Run

```bash
pnpm -C examples/autogen start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.

See the canonical shared scenario: [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).
