# Delegated Authorization Design

## Status

Non-normative (developer documentation)






> **Status: Superseded - implemented as DelegationV1 (v1.3+)**
>
> This document was a pre-implementation design note for delegated agent authorization.
> All open questions and proposed implementation steps below have been resolved and shipped.
>
> For the current normative specification, see:
> - [`SPEC.md §5`](../../SPEC.md) - DelegationV1 artifact definition and verification rules
> - [`docs/spec/delegation-v1.md`](../spec/delegation-v1.md) - detailed implementation spec
> - [`packages/core/src/delegation/`](../../packages/core/src/delegation/) - reference implementation
> - [`packages/conformance/vectors/`](../../packages/conformance/vectors/) - conformance vectors

---

This document prepares the v2 design direction for delegated agent authorization.

It is a design note, not a protocol specification.
It does not change the current v1.x protocol semantics, artifact formats, or verifier behavior.

Current protocol line:

`(intent, state, policy) -> deterministic decision`

Current execution model:

- `AuthorizationV1` may be emitted on `ALLOW`
- the PEP verifies authorization before execution
- snapshot, audit chain, and verification envelope remain the existing evidence path

## Problem

Multi-agent systems often need one agent to authorize or constrain another.

Examples include:

- a planner agent delegating execution to worker agents
- an orchestrator delegating limited authority to specialized execution agents
- an external service performing actions under reduced authority granted by another principal

Without bounded delegation, a child or downstream agent may execute outside the intended scope, budget, or time window.

## Design Goal

Support delegated authority between agents while preserving deterministic authorization and compatibility with the existing OxDeAI verification model.

The delegated model should allow:

- a parent authority source
- a constrained delegated scope
- deterministic child evaluation under that scope
- audit continuity across parent and child execution paths

## Proposed Concept

The v2 design direction introduces a conceptual artifact:

`DelegatedAuthorizationV1`

This is not implemented in the current protocol line.
It is a possible future artifact for expressing bounded delegated authority.

### Conceptual Fields

Potential fields may include:

- `issuer`
- `delegate`
- parent authorization reference
- delegated scope constraints
- expiration
- policy binding
- signature metadata

The conceptual purpose of those fields is:

- identify the authority source
- identify the delegate principal
- bind delegation to a parent authorization or equivalent parent authority context
- constrain what the delegate may do
- constrain when the delegated authority expires
- preserve policy and verification binding

### Bounded Delegation Requirement

Delegated authority must remain bounded by the parent authorization context.

That means a delegate cannot gain broader authority than the parent scope that enabled the delegation.

Examples of bounded scope include:

- reduced budget
- narrower action types
- narrower target or resource scope
- shorter lifetime
- tighter audience or execution context binding

## Execution Model

Conceptually, a delegated execution path may look like this:

```text
parent authority
  -> delegated authorization artifact
  -> child agent proposes intent
  -> child intent + delegated state/policy context
  -> policy enforcement
  -> execution authorization
  -> PEP verification
  -> side effect or refusal
```

One possible evaluation shape is:

```text
parent authorization
  -> delegation artifact
  -> child intent evaluation
  -> policy enforcement
  -> execution authorization
```

Deterministic evaluation is preserved if:

- the delegated scope is explicit
- the delegated context is part of the evaluated state or bound authorization context
- child intents are normalized deterministically
- evaluation still resolves to a deterministic decision for the same inputs

The v2 design should preserve the core OxDeAI contract rather than replace it.

## Security Considerations

Delegated authorization must preserve fail-closed behavior.

Important constraints include:

- delegation scope restriction
- short and explicit expiration windows
- non-transferability of delegated authority unless explicitly designed otherwise
- audit chain continuity from delegation to downstream execution
- compatibility with existing verification expectations

Key security questions for a future implementation include:

- how the parent authority reference is bound to the delegated artifact
- how replay and reuse constraints apply across parent and child contexts
- how single-use or bounded-use semantics should apply to delegated rights
- how delegated authority is prevented from being re-delegated without explicit design support

## Verification Compatibility

Delegation must not break the current verification model.

In particular, future delegated flows should remain compatible with:

- `verifyAuthorization`
- `verifyEnvelope`
- existing snapshot and audit evidence handling

That does not require v1.x artifacts to change today.
It means a future delegated design should preserve compatibility with the existing verification pipeline and rely on additive protocol evolution where necessary.

Delegated actions should remain verifiable through the same evidence concepts:

- evaluated state
- authorization decision
- execution or refusal path
- audit continuity
- envelope verification

## Open Questions

The main open design questions for v2 include:

- whether delegation should reference a parent `AuthorizationV1` directly or a parent authority context indirectly
- whether delegated rights are single-use, bounded-use, or policy-defined
- how delegated scope should be canonically represented without weakening deterministic evaluation
- how delegated identities and audiences should be bound for relying-party verification
- whether delegation should be strictly non-transitive in the first version
- how audit events should represent delegation lineage without breaking existing audit compatibility

## Possible Future Implementation Steps

Future implementation work may include:

1. define the canonical delegated artifact schema
2. define deterministic hashing and binding rules for delegated scope
3. specify relying-party verification requirements for delegated artifacts
4. define audit lineage expectations for delegated execution paths
5. add conformance vectors for delegated authorization verification
6. add example multi-agent delegated flows in adapter demos

## Related References

- [`ROADMAP.md`](../../ROADMAP.md)
- [`PROTOCOL.md`](../../PROTOCOL.md)
- [`SPEC.md`](../../SPEC.md)
- [`docs/adapter-contract.md`](../adapter-contract.md)
- [`docs/pep-production-guide.md`](../pep-production-guide.md)
