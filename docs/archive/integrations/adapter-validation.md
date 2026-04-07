# Adapter Validation

## Status

Non-normative (developer documentation)






## Purpose

Adapter validation gates exist to prove two integration-level properties across maintained OxDeAI adapters:

- deterministic integration behavior
- execution-boundary enforcement before side effects

## Scope

These checks are integration validation gates.
They do not change protocol semantics, authorization artifacts, audit formats, or verifier behavior.

## Validation Dimensions

Maintained adapters are validated in two classes:

- deterministic behavior checks
- authorization boundary enforcement checks

## Deterministic Behavior Checks

Maintained adapter demos SHOULD validate the canonical shared scenario outcome:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Raw runtime actions MAY differ across adapters.
Normalized intent semantics, decision sequence, and verification outcome MUST remain equivalent.

Reference scenario:

- [`shared-demo-scenario.md`](./shared-demo-scenario.md)

## Authorization Boundary Enforcement Checks

Maintained adapters MUST demonstrate:

- a denied action does not execute
- a missing authorization fails closed before execution
- the refusal path is explicit
- the auditable envelope still verifies successfully for the canonical scenario

For the current demo line, this is validated by:

- asserting the third action is `DENY`
- asserting only two execution events occur
- asserting a synthetic `ALLOW` without `Authorization` throws before execution

Adapter-specific invalid-signature or forged-authorization runtime checks MAY be added when the integration performs full verifier-bound production wiring in the demo path.

## Recommended Minimum Adapter Validation Matrix

- allowed action executes
- denied action is refused
- missing authorization is rejected before execution
- envelope verifies successfully
- deterministic scenario outcome matches `ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`

## CI Guidance

The repository uses one lightweight adapter validation command:

```bash
pnpm validate:adapters
```

This command builds each maintained adapter example, runs the shared scenario, and checks:

- the visible semantic outcome
- denied-action non-execution
- missing-authorization fail-closed behavior

## Local Developer Guidance

Validate all maintained adapters:

```bash
pnpm validate:adapters
```

Validate one adapter:

```bash
pnpm -C examples/openai-tools validate
pnpm -C examples/langgraph validate
pnpm -C examples/crewai validate
pnpm -C examples/openai-agents-sdk validate
pnpm -C examples/autogen validate
pnpm -C examples/openclaw validate
```
