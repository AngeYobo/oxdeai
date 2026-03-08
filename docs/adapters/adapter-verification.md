# Adapter Verification

This document defines a lightweight adapter verification check for OxDeAI runtime integrations.

## Purpose

Ensure adapter demos preserve OxDeAI boundary semantics:

- deterministic PDP decision behavior
- authorization-gated execution
- no execution on `DENY`
- successful envelope verification

## Script

- [`scripts/adapter-check/verify-adapter.ts`](../../scripts/adapter-check/verify-adapter.ts)

## What It Verifies

For each target adapter demo:

1. **PDP sequence check**  
   Expected summary: `Allowed: 2` and `Denied: 1`.
2. **Authorization boundary check**  
   Demo output must include explicit authorization-gating signal (`No Authorization = no execution`).
3. **DENY enforcement check**  
   `BUDGET_EXCEEDED` must appear and no subsequent execution marker is allowed.
4. **Envelope verification check**  
   Output must show `verifyEnvelope` with `status: ok`.

## Supported Targets

- `examples/openai-tools`
- `examples/langgraph`

## Usage

From repo root:

```bash
pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts
```

Single adapter:

```bash
pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter openai-tools
pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter langgraph
```

## Output

The script prints per-adapter `PASS`/`FAIL` and per-check status:

- PDP expected sequence
- authorization required before execution
- deny prevents execution
- verifyEnvelope success

Exit codes:

- `0` all selected adapters passed
- `1` one or more adapter checks failed
- `2` usage/argument error
