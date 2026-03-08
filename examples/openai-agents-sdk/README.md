# OpenAI Agents SDK Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

## Run

```bash
pnpm -C examples/openai-agents-sdk start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.
