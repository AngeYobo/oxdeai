# OxDeAI-core

Deterministic economic authorization protocol for autonomous systems.

OxDeAI-core hosts OxDeAI protocol specifications and the TypeScript reference stack.

OxDeAI provides fail-closed policy evaluation for autonomous actions under explicit economic constraints (budget, caps, velocity, allowlists), with cryptographic authorization and tamper-evident audit evidence.

## Current Milestone

- `v1.1` Authorization Artifact: complete
- `v1.2` Non-Forgeable Verification: complete
- `v1.3` Guard Adapter + Integration Surface: substantially complete
- Next: `v1.4` ecosystem adoption

## Core Principles

- Deterministic evaluation
- Fail-closed semantics
- Explicit invariants
- Cryptographic authorization
- AuthorizationV1 pre-execution gating
- Non-forgeable verification (Ed25519 + keyset)
- Hash-chained audit logs
- Stateless verifiability (snapshot/audit/envelope)
- Property testing (fuzz + meta-property)

## Repo Layout

Protocol packages:
- `packages/core` - protocol reference implementation
- `packages/sdk` - integration SDK surface (guard adapter + client helpers)
- `packages/conformance` - frozen vectors and compatibility validator

Tooling package:
- `packages/cli` - protocol-oriented local tooling (`build`, `verify`, `replay`)

Examples:
- `examples/openai-tools` - protocol reference boundary demo
- `examples/langgraph` - framework integration boundary demo

Specifications and docs:
- `SPEC.md`, `SECURITY.md`, `PROTOCOL.md`

## Examples

- [`examples/openai-tools`](./examples/openai-tools) - protocol reference demo
  - canonical PDP/PEP boundary flow
  - deterministic intent -> decision -> authorization -> audit -> envelope verification

- [`examples/langgraph`](./examples/langgraph) - framework integration demo
  - same boundary model embedded in a LangGraph workflow
  - frameworks propose actions; OxDeAI authorizes execution

## Stack Placement

`framework/runtime -> OxDeAI authorization boundary -> tool execution`

- Framework/runtime proposes actions.
- OxDeAI PDP evaluates intent and emits authorization on `ALLOW`.
- PEP verifies authorization and either executes or refuses.

## Quickstart

Install dependencies:
```bash
pnpm install
```

## Release

- [Release checklist](./docs/release-checklist.md)
- [Release policy](./RELEASE.md)

## Protocol Stack Release v1.2.0

This release introduces non-forgeable verification through Ed25519 signatures and KeySet-based issuer verification.

The OxDeAI protocol stack now provides:

- cryptographically verifiable authorization artifacts
- deterministic policy evaluation
- tamper-evident audit chains
- stateless verification envelopes

The protocol is validated through the OxDeAI conformance suite.

## Validation Snapshot

Latest local validation (2026-03-08):

- `pnpm build` pass
- `pnpm -C packages/conformance validate` pass (94 assertions)
- `pnpm -r test` pass
- `pnpm -C examples/openai-tools start` pass (`ALLOW`, `ALLOW`, `DENY`, envelope `ok`)
- `pnpm -C examples/langgraph start` pass (`ALLOW`, `ALLOW`, `DENY`, envelope `ok`)

## Protocol Flow (v1.2.x)

- OxDeAI issues `AuthorizationV1` artifacts on `ALLOW`.
- External relying parties verify `AuthorizationV1` before execution.
- Verification envelopes remain post-execution proof artifacts.
