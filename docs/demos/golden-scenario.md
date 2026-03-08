# Golden Scenario

This document defines the canonical cross-runtime OxDeAI demonstration scenario.

## Scenario Definition

Policy profile:

- `budget = 1000` (minor units)
- `max_per_action = 500` (minor units)

Action profile:

- tool/action: GPU provisioning (`provision_gpu`)
- deterministic cost per call: `500`

Expected sequence:

1. call 1 -> `ALLOW`
2. call 2 -> `ALLOW`
3. call 3 -> `DENY` with `BUDGET_EXCEEDED`

## Required Demonstration Properties

Each adapter demo MUST demonstrate:

- deterministic PDP evaluation for each proposed call
- authorization gating before execution
- no side-effect execution on `DENY`
- verification envelope generation from snapshot + audit events
- `verifyEnvelope()` returns `ok`

## Expected Output Pattern

The runtime-level result pattern MUST be:

```text
ALLOW
ALLOW
DENY
verifyEnvelope: ok
```

Equivalent formatting is allowed, but decision order and verification outcome must remain the same.

## Current Reference Demos

- [`examples/openai-tools`](../../examples/openai-tools)
- [`examples/langgraph`](../../examples/langgraph)
- [`examples/crewai`](../../examples/crewai)
- [`examples/openai-agents-sdk`](../../examples/openai-agents-sdk)
- [`examples/autogen`](../../examples/autogen)
- [`examples/openclaw`](../../examples/openclaw)

## Adapter Requirement

Any new adapter MUST replicate this scenario before being treated as integration-complete.
