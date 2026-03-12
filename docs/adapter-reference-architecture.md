# Adapter Reference Architecture

This document defines the reference integration shape for embedding OxDeAI under agent runtimes.

Shared adapter contract:
- [`docs/adapter-contract.md`](./adapter-contract.md)

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

Adapters MAY sit between raw action surfaces and OxDeAI intent evaluation.
They are responsible for deterministic normalization before policy evaluation so that equivalent actions map to equivalent intents within the integration.
OxDeAI remains the authorization layer at the execution boundary, not the action-expression layer.

Adapters MAY also enrich policy state with deterministic execution context before invoking the OxDeAI PDP.
Examples include execution-history flags, previous sensitive operations, resource-scope transitions, and workflow-phase indicators.
Any such enrichment MUST remain deterministic and reproducible for the same evaluated situation.

## Shared Adapter Contract

The shared adapter contract is documented in [`docs/adapter-contract.md`](./adapter-contract.md).

In that contract, the adapter is responsible for normalization plus authorization-boundary wiring.
The adapter is not the protocol and it is not the runtime.
It sits between the raw action surface and OxDeAI intent/state evaluation.

Current runtime-style demo coverage in this repository:
- OpenAI tools reference boundary demo
- LangGraph
- CrewAI
- OpenAI Agents SDK
- AutoGen
- OpenClaw
