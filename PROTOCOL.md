# OxDeAI Protocol (v1.3.x)

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

### Action Surface Independence

OxDeAI is independent from the action interface used by agent runtimes.

Agent runtimes may express actions through various interfaces, including:

* structured tool calls
* CLI-style command execution (e.g. `run("command")`)
* workflow engines
* MCP tool invocation
* framework-specific tool adapters

OxDeAI does not define how actions are expressed.

Instead, runtimes SHOULD normalize proposed actions into a deterministic **intent** before submitting them to the policy engine.

```
action surface
→ normalization
→ intent
→ OxDeAI PDP evaluation
→ AuthorizationV1
→ PEP enforcement
→ side effect
```

This ensures that OxDeAI secures the **execution boundary**, independent of the upstream action surface.
This is a documentation clarification of interface-independence, not a new protocol artifact layer.

### Intent Normalization

Before policy evaluation, runtimes SHOULD normalize proposed actions into the intent representation used by their OxDeAI integration.

Normalization preserves deterministic evaluation and policy portability across different action surfaces.
The protocol does not currently mandate one universal normalization schema for all runtimes.

Implementations MUST ensure that supported action surfaces map to intent deterministically.
Equivalent external actions SHOULD map to equivalent intent representations within the implementation that evaluates and enforces them.

## 3) Artifact Flow

![Agent authorization boundary](./docs/diagrams/agent-authorization-boundary.svg)

Expanded flow:

1. Runtime submits `intent` with current policy `state`.
2. Engine evaluates policy modules deterministically.
3. Engine returns `ALLOW` or `DENY`.
4. On `ALLOW`, runtime commits state/audit and executes side effect.
5. Runtime can package artifacts into `VerificationEnvelopeV1`.
6. Third parties verify envelope offline via stateless verifiers.

Diagram source/editing policy:
- [`docs/diagrams/README.md`](./docs/diagrams/README.md)

## Architecture

OxDeAI sits between agent runtimes and external systems as a deterministic authorization boundary.

![PDP and PEP flow](./docs/diagrams/pdp-pep-flow.svg)

- `PDP` evaluates policy deterministically over `intent,state`.
- `AuthorizationV1` is emitted only on `ALLOW`.
- `PEP` enforces authorization verification before execution.
- External side effects must not execute on `DENY`.

Verification artifacts are generated and validated through the envelope flow:

![Verification envelope flow](./docs/diagrams/verification-envelope-flow.svg)

## 4) Protocol Artifacts (Overview)

OxDeAI v1.3.x protocol surface centers on:

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

## `@oxdeai/cli`

Operational tooling layer for local artifact workflows (`build`, `verify`, `replay`).
It is versioned independently from the protocol stack and does not redefine protocol semantics.

## 7) Deterministic Boundary

Protocol-critical paths are deterministic:

- canonical serialization before hashing
- stable ordering rules
- no hidden entropy in verification functions

This is what makes offline verification and cross-runtime conformance possible.

## Future Policy Dimensions

OxDeAI already evaluates policy over `(intent, state)`.
Richer authorization semantics can therefore be expressed through deterministic state modeling without changing the current protocol contract.

### 1) Context-Aware Authorization

Policy evaluation MAY depend on contextual state accumulated during execution.

Examples of contextual state include:

- remaining budget
- action counters
- resource scopes
- environment flags
- execution phase

Context-aware decisions are already expressible through the `state` input without protocol changes.

### 2) Execution Path Policies

Execution path policies depend on sequences of actions rather than one action in isolation.

Examples include:

- `read_secret` -> forbid `external_upload`
- `access_sensitive_resource` -> restrict network access
- `deployment_started` -> restrict destructive actions

The OxDeAI protocol does not currently define path-policy primitives.
Instead, runtimes MAY encode relevant execution history, derived flags, or workflow markers into the policy state used during evaluation.

### 3) Delegated Authority

Delegated authority describes bounded authorization in multi-agent systems.

For example, a parent agent may authorize a child agent with reduced:

- budget
- action types
- resource scope
- time window

Future protocol versions MAY introduce explicit delegation artifacts such as `DelegatedAuthorizationV1`.
For the current protocol line, delegation can be implemented through state-scoped policies that preserve deterministic evaluation over `(intent, state, policy)`.

## 8) Versioning and Stability

v1.3.x is the current protocol line for the guard/integration surface on top of the v1.2 non-forgeable verification baseline (`alg`/`kid`/`signature` with Ed25519).
Legacy v1.0.x compatibility paths MAY remain supported by implementations where explicitly documented.

Incompatible changes to canonical artifacts, verification result semantics, or envelope format require a major protocol version.

See release policy:

- [`RELEASE.md`](./RELEASE.md)

## 9) Where to Go Next

- Full protocol companion spec: [`SPEC.md`](./SPEC.md)
- Relying-party execution gate contract: [`SPEC.md` §9](./SPEC.md#9-relying-party-contract)
- Production PEP wiring guide: [`docs/pep-production-guide.md`](./docs/pep-production-guide.md)
- Legacy v1.0.2 normative profile (archival): [`protocol/protocol.md`](./protocol/protocol.md)
- Threat model details: [`protocol/threat-model.md`](./protocol/threat-model.md)
- Envelope profile details: [`protocol/envelope.md`](./protocol/envelope.md)
- Non-forgeable verification design notes: [`docs/NON_FORGEABLE_VERIFICATION.md`](./docs/NON_FORGEABLE_VERIFICATION.md)
