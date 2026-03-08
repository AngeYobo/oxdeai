# Production PEP Wiring Guide

This guide describes a minimal production wiring pattern for a Policy Enforcement Point (PEP) using OxDeAI.

Reference architecture:
- [`docs/adapter-reference-architecture.md`](./adapter-reference-architecture.md)
- diagram workflow: [`docs/diagrams/README.md`](./diagrams/README.md)

## Scope

Applies to services that execute external side effects (tools, provisioning, payments, API calls) and must enforce OxDeAI authorization before execution.

## Required Inputs

- Trusted issuer configuration
- Trusted audience identifier for the current service
- Trusted KeySet(s) for signature verification
- Current expected `policy_id` context
- Consumed authorization store (`auth_id` single-use tracking)

## Enforcement Sequence

Before executing an external action, the PEP MUST:

1. Parse authorization artifact and reject malformed payloads.
2. Verify signature and key resolution (`alg`, `kid`, trusted issuer keyset).
3. Verify issuer and audience binding.
4. Verify `decision == ALLOW`.
5. Verify not expired (`expiry > now`).
6. Verify policy binding (`policy_id` equals expected policy context).
7. Verify intent binding (`intent_hash` equals hash of the exact action about to execute).
8. Verify state binding (`state_hash` matches required state snapshot context).
9. Verify replay protection (`auth_id` not previously consumed).

If any step fails, execution MUST NOT occur.

## Execution and Consumption

On successful verification:

1. Execute the side effect.
2. Persist `auth_id` as consumed.
3. Persist execution/audit evidence as required by your environment.

The consumed write SHOULD be durable and atomic relative to execution outcome handling.

## Failure Policy

PEP implementations SHOULD fail closed for:

- unknown issuer
- unknown `kid`
- unsupported `alg`
- invalid signature
- policy mismatch
- audience mismatch
- replayed `auth_id`
- verification ambiguity

## Minimal SDK Pattern

Use `@oxdeai/sdk` guard boundary:

- PDP: `PolicyEngine.evaluatePure(...)`
- PEP: `createGuard(...)` callback boundary

The callback executes only on verified `ALLOW`; denied or invalid authorization paths do not execute.

## Operational Notes

- Keep authorization TTL short.
- Keep consumed authorization storage scoped by issuer/audience/policy context.
- Rotate signing keys with explicit `kid` and validity windows.
- Monitor verification failures and replay rejections as security signals.
