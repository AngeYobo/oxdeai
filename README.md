# OxDeAI-core

Deterministic Economic Guardrails Engine for Autonomous Systems.

OxDeAI-core hosts the OxDeAI protocol docs and the TypeScript reference implementation.

OxDeAI-core provides a formally specified, fail-closed policy engine for controlling
autonomous agents (AI agents, workflows, bots) under strict economic constraints
(budget, caps, velocity, allowlists), with cryptographic authorization and tamper-evident audit logs.

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

- `packages/core` - policy engine + invariants enforcement
- `packages/conformance` - frozen vectors + conformance validator
- `protocol` - normative protocol specification
- `packages/sdk` - integration SDK
- `packages/cli` - CLI harness / demo
- `packages/core/tests` - unit + invariants + fuzz/property tests
- `examples` - reference integrations (`gpu-guard`, `langgraph`, `openai-tools`)
- `docs` - architecture, invariants, and verification notes

## Examples

- [`examples/openai-tools`](./examples/openai-tools) - protocol reference demo
  - canonical OxDeAI PDP/PEP boundary flow
  - deterministic intent -> decision -> authorization -> audit -> envelope verification

- [`examples/langgraph`](./examples/langgraph) - framework integration demo
  - same OxDeAI boundary model embedded in a LangGraph workflow
  - demonstrates that frameworks propose actions, while OxDeAI authorizes execution

## Quickstart

Install dependencies:
```bash
pnpm install
```

## Release

- [Release checklist](./docs/release-checklist.md)

## Protocol Stack Release v1.2.0

This release introduces non-forgeable verification through Ed25519 signatures and KeySet-based issuer verification.

The OxDeAI protocol stack now provides:

- cryptographically verifiable authorization artifacts
- deterministic policy evaluation
- tamper-evident audit chains
- stateless verification envelopes

The protocol is validated through the OxDeAI conformance suite.

## Protocol Flow (v1.2.0)

- OxDeAI issues `AuthorizationV1` artifacts on `ALLOW`.
- External relying parties verify `AuthorizationV1` before execution.
- Verification envelopes remain post-execution proof artifacts.
