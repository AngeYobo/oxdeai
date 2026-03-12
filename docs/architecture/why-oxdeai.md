# Why OxDeAI

## Introduction

OxDeAI exists to enforce deterministic authorization at the execution boundary of autonomous systems.

It is not a runtime, orchestration engine, or prompt guardrail layer. It is the protocol and reference stack that decides whether a proposed external action is allowed to execute under the current policy state.

## The Agent Execution Problem

Modern agent runtimes can trigger real side effects:

- external API calls
- cloud provisioning
- payments
- workflow actions
- command execution

These actions are where economic and operational risk becomes real. A model output is not yet a side effect. A provider call, infrastructure action, or paid tool invocation is.

## Why Prompt Guardrails Are Insufficient

Prompt and output guardrails operate upstream from execution. They may reduce unsafe content or shape responses, but they do not themselves guarantee that a side effect will be blocked before execution.

An autonomous system can still produce action proposals that look valid to the runtime and continue to cross tool or provider boundaries unless an execution gate exists.

OxDeAI addresses that narrower problem: whether a proposed action is authorized to execute now.

## The Execution Authorization Boundary

OxDeAI sits between the runtime and the external system.

```text
runtime / agent
  -> adapter normalization
  -> intent + state
  -> OxDeAI PDP
  -> AuthorizationV1 on ALLOW
  -> PEP verifyAuthorization
  -> side effect or refusal
```

The control point is pre-execution:

- `DENY` means the side effect does not execute
- `ALLOW` may emit `AuthorizationV1`
- the PEP verifies that authorization before the side effect occurs

## OxDeAI Architecture

The architecture separates policy evaluation from execution enforcement.

```text
raw action surface
  -> adapter normalization
  -> deterministic intent
  -> current policy state
  -> PDP evaluation
  -> authorization artifact on ALLOW
  -> PEP verification gate
  -> external system
  -> audit chain + snapshot
  -> verification envelope
```

Key roles:

- adapter: maps a runtime-specific action surface into deterministic intent
- PDP: evaluates `(intent, state, policy)` deterministically
- PEP: verifies authorization before side effects
- evidence path: preserves snapshot, audit events, and verification envelope for later verification

## Deterministic Evaluation Model

The protocol contract is:

`(intent, state, policy) -> deterministic decision`

That means the same evaluated situation produces the same semantic result. The protocol depends on deterministic serialization, stable verification behavior, and explicit state transitions.

The current line does not require one universal raw action schema. It does require deterministic normalization within each integration.

## Authorization Artifacts

On `ALLOW`, the engine may emit `AuthorizationV1`.

That artifact binds the authorization decision to:

- the evaluated intent
- the policy identity
- the state snapshot hash
- issuer and audience context
- expiry and signature metadata

It is not a post-fact report. It is the pre-execution artifact used at the authorization boundary.

## Verification Evidence

OxDeAI also preserves a verification path after execution or refusal:

- snapshot captures the evaluated state
- audit events record proposed actions, decisions, and execution or refusal
- verification envelope packages snapshot plus audit evidence

`verifyEnvelope()` provides stateless verification of that packaged evidence under the selected mode.

This evidence path is useful for:

- reproducible integration demos
- relying-party review
- independent verification
- post-execution reasoning about what was evaluated and what was refused

## Integration Architecture

OxDeAI is interface-agnostic. Upstream action surfaces may include:

- structured tool calls
- CLI-style command execution
- workflow nodes
- MCP-mediated invocation
- framework-specific adapters

Those action surfaces are not the protocol. Integrations normalize them into intent before evaluation.

Practical integration shape:

1. runtime proposes action
2. adapter normalizes action into deterministic intent
3. current state is supplied to the PDP
4. PDP returns `ALLOW` or `DENY`
5. on `ALLOW`, `AuthorizationV1` may be emitted
6. PEP verifies authorization before execution
7. audit and verification artifacts remain available for later checks

## Example Execution Flow

The maintained demos use a shared canonical scenario:

- first action: `ALLOW`
- second action: `ALLOW`
- third action: `DENY`
- `verifyEnvelope() => ok`

That scenario demonstrates:

- deterministic evaluation under the same policy model
- authorization at the execution boundary
- explicit refusal on `DENY`
- reproducible verification evidence

The demos differ by runtime shape, not by OxDeAI semantics.

## Related References

- [`README.md`](../../README.md)
- [`PROTOCOL.md`](../../PROTOCOL.md)
- [`SPEC.md`](../../SPEC.md)
- [`docs/adapter-contract.md`](../adapter-contract.md)
- [`docs/pep-production-guide.md`](../pep-production-guide.md)
- [`docs/integrations/README.md`](../integrations/README.md)
- [`docs/integrations/shared-demo-scenario.md`](../integrations/shared-demo-scenario.md)
- [`docs/cases/README.md`](../cases/README.md)
