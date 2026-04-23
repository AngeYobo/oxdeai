# OxDeAI v1.3 — Stable Execution Authorization Protocol

## Status

Historical announcement draft. This file is not release policy and must not be used as a release runbook.

OxDeAI is now Stable: deterministic execution authorization with cross-language verification. Canonicalization, authorization, PEP, and delegation vectors are published and verified.

## The Gap

Current systems:
- rely on retries
- rely on prompts
- rely on monitoring

None of these enforce execution.

OxDeAI introduces a non-bypassable execution boundary.

## What is proven
- Canonicalization locked
- Authorization / PEP / Delegation vectors passing
- TypeScript / Go / Python parity (verified in CI)

## Core idea
```
proposal → authorization → execution
```

## Key claim
Agents can propose actions. OxDeAI decides if they are allowed to execute.

## Why it matters
- Removes execution from the model loop
- Eliminates best-effort enforcement
- Enables verifiable control

No authorization → no execution.

## One-liners

Short:

"Agents propose actions. OxDeAI decides if they are allowed to execute."

Strong:

"Without an execution boundary, agents are not production-safe."
