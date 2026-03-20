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

### DelegationV1 boundary checks (`examples/delegation`)

The delegation demo is verified separately with different expected output (`ALLOW`, `ALLOW`, `DENY`, `DENY`):

1. **Delegation chain check** - `verifyDelegationChain` passes for valid scope + unexpired delegation
2. **Scope enforcement** - DENY when child requests a tool not in delegated scope
3. **Expiry enforcement** - DENY when delegation has expired at verification time
4. **setState skip** - state is not mutated on the delegation execution path

### Cross-adapter invariant tests (`@oxdeai/compat`)

`packages/compat/src/test/cross-adapter.test.ts` (CA-1–CA-10) validates:
- Same normalized intent + same policy state + same policy configuration produces identical authorization decisions across LangGraph, OpenAI Agents SDK, and CrewAI adapters
- I6 evaluation isolation: each adapter receives a `structuredClone` of shared state to prevent `deepMerge` mutation side-effects between callers

Run with:
```bash
pnpm -C packages/compat test
```

## Supported Targets

- `examples/openai-tools`
- `examples/langgraph`
- `examples/openclaw`
- `examples/delegation` (DelegationV1 boundary, separate checks)

## Usage

From repo root:

```bash
pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts
```

Single adapter:

```bash
  pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter openai-tools
  pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter langgraph
  pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter openclaw
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
