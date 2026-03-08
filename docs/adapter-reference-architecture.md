# Adapter Reference Architecture

This document defines the reference integration shape for embedding OxDeAI under agent runtimes.

## Layer Model

- **PDP (Policy Decision Point)**: deterministic policy evaluation over `(intent, state)`.
- **PEP (Policy Enforcement Point)**: execution boundary that verifies authorization and either executes or refuses side effects.

## Adapter Sidecar Architecture

![Adapter sidecar architecture](./diagrams/adapter-sidecar-architecture.svg)

Related boundary view:
- [`Agent authorization boundary`](./diagrams/agent-authorization-boundary.svg)

Diagram source/editing policy:
- [`docs/diagrams/README.md`](./diagrams/README.md)

## Component Roles

- **Agent runtime**: proposes actions; does not directly authorize side effects.
- **Adapter**: translates runtime-specific action proposals into OxDeAI intent inputs and maps outputs back to runtime conventions.
- **SDK guard**: standard integration boundary (`createGuard`) that enforces execute-or-refuse behavior around callbacks.
- **PDP**: returns deterministic `ALLOW`/`DENY` and emits authorization/state transition data for `ALLOW`.
- **PEP**: verifies authorization constraints (issuer, audience, policy, intent/state binding, expiry, replay) before execution.
- **Verification artifacts**: audit events, canonical snapshot, and envelope provide offline/stateless evidence and replay-grade verification.

## Framework-Agnostic Property

This architecture is framework-agnostic because runtimes interact through the same boundary contract:

- runtime proposes action
- OxDeAI decides and emits authorization artifacts
- PEP enforces authorization before side effects
- artifacts are verified with common stateless verifiers

Framework choice changes adapter code, not protocol semantics.
