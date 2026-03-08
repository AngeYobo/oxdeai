# OxDeAI Roadmap Status

Last updated: 2026-03-08

## Version Snapshot (from package.json)

- `@oxdeai/core`: `1.2.0`
- `@oxdeai/sdk`: `1.2.0`
- `@oxdeai/conformance`: `1.2.0`
- `@oxdeai/cli`: `0.2.0`
- `@oxdeai/tests`: `0.1.0`
- `@oxdeai/example-openai-tools`: `1.0.0`
- `@oxdeai/example-gpu-guard`: no `version` field
- workspace root `oxdeai-core`: no `version` field

## Validation Snapshot

Latest local validation (2026-03-08):

- [x] `pnpm build`
- [x] `pnpm -C packages/conformance validate` (94 assertions passed)
- [x] `pnpm -r test` (core/cli/sdk/tests passing)
- [x] `pnpm -C examples/openai-tools start` (ALLOW, ALLOW, DENY; envelope `ok`)
- [x] `pnpm -C examples/langgraph start` (ALLOW, ALLOW, DENY; envelope `ok`)

## Protocol Milestone Status

- `v1.1` — Authorization Artifact: `DONE`
- `v1.2` — Non-Forgeable Verification: `DONE`
- `v1.3` — Guard Adapter + Integration Surface: `SUBSTANTIALLY COMPLETE`
- `v1.4` — Ecosystem Adoption: `NEXT`
- `v3.x` — Public Proof Infrastructure: `LATER`

Working integration demonstrations:

- [`examples/openai-tools`](./examples/openai-tools) — protocol reference demo
- [`examples/langgraph`](./examples/langgraph) — framework integration demo

## Status Legend

- `Done`: implemented and documented in repo.
- `In Progress`: partial implementation exists; acceptance criteria not fully met.
- `Not Started`: no substantive implementation in repo.

## v1.1

### AuthorizationV1 first-class

Status: `Done`

Evidence:

- [`packages/core/src/types/authorization.ts`](./packages/core/src/types/authorization.ts)
- [`packages/core/src/policy/PolicyEngine.ts`](./packages/core/src/policy/PolicyEngine.ts)
- [`SPEC.md`](./SPEC.md)

Acceptance criteria:

- [x] Authorization artifact emitted on `ALLOW`.
- [x] Protocol fields defined and documented.
- [x] Verification primitive exposed.

### Relying-party contract

Status: `Done`

Evidence:

- [`SPEC.md`](./SPEC.md#9-relying-party-contract)
- [`examples/openai-tools/src/pep.ts`](./examples/openai-tools/src/pep.ts)

Acceptance criteria:

- [x] Normative verification checklist present.
- [x] Fail-closed execution rule documented.
- [x] Single-use/replay rule documented.

## v1.2

### Non-forgeable verification

Status: `Done`

Evidence:

- [`packages/core/src/verification/verifyAuthorization.ts`](./packages/core/src/verification/verifyAuthorization.ts)
- [`packages/core/src/verification/verifyEnvelope.ts`](./packages/core/src/verification/verifyEnvelope.ts)
- [`packages/conformance/vectors/authorization-signature-verification.json`](./packages/conformance/vectors/authorization-signature-verification.json)
- [`packages/conformance/vectors/envelope-signature-verification.json`](./packages/conformance/vectors/envelope-signature-verification.json)

Acceptance criteria:

- [x] Signature validation integrated into authorization verifier.
- [x] Envelope signature profile supported.
- [x] Conformance vectors cover invalid signature/unknown kid/unknown alg paths.

### Ed25519

Status: `Done`

Evidence:

- [`packages/core/src/crypto/signatures.ts`](./packages/core/src/crypto/signatures.ts)

Acceptance criteria:

- [x] Ed25519 signing and verification available.
- [x] Deterministic signature input function exists.

### alg / kid

Status: `Done`

Evidence:

- [`packages/core/src/types/authorization.ts`](./packages/core/src/types/authorization.ts)
- [`packages/core/schemas/authorization.schema.json`](./packages/core/schemas/authorization.schema.json)
- [`SPEC.md`](./SPEC.md)

Acceptance criteria:

- [x] `alg` and `kid` represented in artifact model.
- [x] Verifiers enforce supported alg and key resolution.

### KeySet model

Status: `Done`

Evidence:

- [`packages/core/src/types/keyset.ts`](./packages/core/src/types/keyset.ts)
- [`packages/core/schemas/keyset.schema.json`](./packages/core/schemas/keyset.schema.json)
- [`SPEC.md`](./SPEC.md#10-keyset-and-key-rotation-model)

Acceptance criteria:

- [x] KeySet type and schema exist.
- [x] Verifier resolves keys by issuer+kid+alg.
- [x] Key validity windows handled by verification logic.

## v1.3

### CLI + SDK guard adapter

Status: `Substantially Complete`

Evidence:

- SDK integration surface exists: [`packages/sdk/src/index.ts`](./packages/sdk/src/index.ts)
- Stable guard API exists: [`packages/sdk/src/guard.ts`](./packages/sdk/src/guard.ts)
- SDK guard tests exist: [`packages/sdk/src/guard.test.ts`](./packages/sdk/src/guard.test.ts)
- CLI command surface stabilized: [`packages/cli/src/main.ts`](./packages/cli/src/main.ts)

Exit criteria:

- [x] Stable guard-adapter API in SDK for common PEP enforcement flow.
- [x] CLI commands for guard setup/verification documented and tested.
- [ ] At least one integration guide for production PEP wiring.

### Easy integrations

Status: `Substantially Complete`

Evidence:

- OpenAI tools integration example: [`examples/openai-tools`](./examples/openai-tools)
- LangGraph integration demo implemented: [`examples/langgraph/src/run.ts`](./examples/langgraph/src/run.ts)
- LangGraph proposal node: [`examples/langgraph/src/graph.ts`](./examples/langgraph/src/graph.ts)

Exit criteria:

- [x] LangGraph integration upgraded from placeholder to runnable example.
- [ ] One additional non-OpenAI integration example added.
- [ ] Quickstart path reduced to minimal steps with copy-paste snippets.

## v1.4+

### Ecosystem adoption

Status: `Not Started`

Exit criteria:

- [ ] Public adopters list with verifiable usage references.
- [ ] External implementation(s) passing conformance.

### More wrappers

Status: `In Progress`

Evidence:

- Wrapper-style examples present in `examples/`.

Exit criteria:

- [ ] Additional wrappers beyond current examples (at least two production-oriented targets).
- [ ] Wrapper docs include threat and trust assumptions.

### Case studies

Status: `Not Started`

Exit criteria:

- [ ] At least two case studies with architecture, controls, and measured outcomes.

## v2.x / v3.x

### Merkle state commitments

Status: `Not Started`

Exit criteria:

- [ ] Canonical Merkle commitment format defined.
- [ ] Inclusion/exclusion proof verification API specified and tested.

### Deterministic receipts

Status: `Not Started`

Exit criteria:

- [ ] Receipt schema and canonical signing format defined.
- [ ] Receipt verification vectors added to conformance.

### Partial state proofs

Status: `Not Started`

Exit criteria:

- [ ] Partial proof format defined.
- [ ] Verification semantics and failure modes documented.
- [ ] Conformance vectors for valid/invalid proofs added.
