# OxDeAI Protocol (v1.2.0)

OxDeAI is a deterministic economic containment protocol for autonomous systems.

This document is the front door:

- what problem OxDeAI solves
- what artifacts it emits
- how to verify those artifacts without running the engine

For normative details (schemas, canonicalization, verifier semantics), see:

- [`SPEC.md`](./SPEC.md)
- [`protocol/protocol.md`](./protocol/protocol.md)

## 1) Problem

Autonomous runtimes fail in repeatable ways:

- runaway spend before operators react
- unbounded concurrency causing amplified side effects
- duplicate execution effects from retries/replays

Observability alone is post-fact.
OxDeAI shifts control to pre-execution policy gating.

## 2) Core Question

OxDeAI answers one protocol question:

`Given intent + state + policy config, is this economically allowed?`

Outputs are deterministic for the same inputs.

If allowed, a signed authorization artifact is emitted.
If denied, execution MUST NOT proceed.

## 3) Artifact Flow

```text
Agent/Runtime
  -> OxDeAI Policy Engine
  -> Decision + AuthorizationV1 (ALLOW only)
  -> External verifier (stateless)
  -> Execution (only if allowed)
  -> Snapshot + Audit -> Verification Envelope
```

Expanded flow:

1. Runtime submits `intent` with current policy `state`.
2. Engine evaluates policy modules deterministically.
3. Engine returns `ALLOW` or `DENY`.
4. On `ALLOW`, runtime commits state/audit and executes side effect.
5. Runtime can package artifacts into `VerificationEnvelopeV1`.
6. Third parties verify envelope offline via stateless verifiers.

## 4) Protocol Artifacts (Overview)

OxDeAI v1.2.0 protocol surface centers on:

- Intent (request + binding fields)
- Canonical snapshot (`formatVersion: 1`)
- AuthorizationV1 (`ALLOW` pre-execution artifact with issuer/audience/intent/state/policy binding)
- non-forgeable authorization signatures (`alg`, `kid`, `signature`)
- Hash-chained audit events
- Verification envelope (`snapshot + events`) with optional signature profile
- KeySet metadata for offline key lookup and rotation windows
- Unified verification result (`ok | invalid | inconclusive`)

See detailed definitions in [`SPEC.md`](./SPEC.md).

## 5) Stateless Verification Surface

The protocol-stable verification APIs are:

- `verifySnapshot(snapshotBytes)`
- `verifyAuditEvents(events, opts?)`
- `verifyEnvelope(envelopeBytes, opts?)`
- `verifyAuthorization(auth, opts?)`

All return unified `VerificationResult`.

Operational meaning:

- `ok`: verification passes under selected mode
- `invalid`: malformed or inconsistent artifacts
- `inconclusive`: not invalid, but insufficient strict anchor evidence

Strict/best-effort behavior and deterministic violation ordering are specified in [`SPEC.md`](./SPEC.md).
Relying-party execution gate requirements are specified in [`SPEC.md` §9](./SPEC.md#9-relying-party-contract).

`verifyAuthorization` is the pre-execution gate.
`verifyEnvelope` remains the post-execution evidence verifier.
Ed25519 + KeySet verification is the preferred non-shared-secret path.

## 6) Package Roles

## `@oxdeai/core`

Reference implementation of the protocol:

- deterministic policy engine
- canonical snapshot codec
- audit chain logic
- stateless verification functions
- envelope codec

## `@oxdeai/conformance`

Protocol truth test:

- frozen vectors for protocol behavior
- validator that checks deterministic equivalence
- cross-implementation baseline for non-TS runtimes

Passing conformance means implementation outputs match frozen protocol artifacts for the targeted version profile.

## `@oxdeai/sdk`

Integration convenience layer on top of `@oxdeai/core`.
It does not redefine protocol semantics.

## 7) Deterministic Boundary

Protocol-critical paths are deterministic:

- canonical serialization before hashing
- stable ordering rules
- no hidden entropy in verification functions

This is what makes offline verification and cross-runtime conformance possible.

## 8) Versioning and Stability

v1.2.0 is the current protocol line for non-forgeable verification (`alg`/`kid`/`signature` with Ed25519).
Legacy v1.0.x compatibility paths MAY remain supported by implementations where explicitly documented.

Incompatible changes to canonical artifacts, verification result semantics, or envelope format require a major protocol version.

See release policy:

- [`RELEASE.md`](./RELEASE.md)

## 9) Where to Go Next

- Full protocol companion spec: [`SPEC.md`](./SPEC.md)
- Relying-party execution gate contract: [`SPEC.md` §9](./SPEC.md#9-relying-party-contract)
- Normative protocol text: [`protocol/protocol.md`](./protocol/protocol.md)
- Threat model details: [`protocol/threat-model.md`](./protocol/threat-model.md)
- Envelope profile details: [`protocol/envelope.md`](./protocol/envelope.md)
- Future v1.2 non-forgeable verification design: [`docs/NON_FORGEABLE_VERIFICATION.md`](./docs/NON_FORGEABLE_VERIFICATION.md)
