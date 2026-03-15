# OxDeAI Roadmap Status

Last updated: 2026-03-15

## Version Snapshot

Protocol stack:
- `@oxdeai/core`: `1.3.1`
- `@oxdeai/sdk`: `1.3.1`
- `@oxdeai/conformance`: `1.3.1`

Adapter packages (all `1.0.0`):
- `@oxdeai/guard`, `@oxdeai/langgraph`, `@oxdeai/openai-agents`, `@oxdeai/crewai`, `@oxdeai/autogen`, `@oxdeai/openclaw`

Tooling:
- `@oxdeai/cli`: `0.2.4` (independent tooling line)

## Current Validation Snapshot

- [x] `pnpm build` passes
- [x] `pnpm -r test` passes (all adapter tests)
- [x] `pnpm -C packages/conformance validate` passes (`94` assertions)
- [x] `node scripts/validate-adapters.mjs` passes (6/6 adapters)
- [x] `examples/openai-tools` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/langgraph` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/crewai` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/openai-agents-sdk` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/autogen` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/openclaw` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)

## Architecture Doctrine

OxDeAI is optimized for:
- easy embedding
- framework-agnostic integration
- authorization-boundary enforcement

OxDeAI is not:
- a replacement runtime
- a full agent framework
- an on-chain-first platform

## Milestones

### v1.1 - Authorization Artifact
Status: `Done`

Delivered:
- `AuthorizationV1` as a first-class protocol artifact
- relying-party / PEP verification contract
- first-class authorization semantics for pre-execution gating

### v1.2 - Non-Forgeable Verification
Status: `Done`

Delivered:
- Ed25519 signature support
- required `alg` / `kid` / `signature` metadata path
- public-key verification primitives
- KeySet model for issuer/key selection and rotation windows
- conformance validation coverage for signature and key-failure paths

### v1.3 - Guard Adapter + Integration Surface
Status: `Done`

Delivered:
- stable SDK guard/integration surface
- OpenAI tools reference boundary demo
- LangGraph integration demo
- production PEP wiring guide
- deterministic envelope verification across demos

References:
- [`examples/openai-tools`](./examples/openai-tools)
- [`examples/langgraph`](./examples/langgraph)
- [`examples/crewai`](./examples/crewai)
- [`examples/openai-agents-sdk`](./examples/openai-agents-sdk)
- [`examples/autogen`](./examples/autogen)
- [`examples/openclaw`](./examples/openclaw)
- [`docs/pep-production-guide.md`](./docs/pep-production-guide.md)

### v1.4 - Ecosystem Adoption
Status: `Done`

Delivered:
- universal execution guard (`@oxdeai/guard`) - single PEP package shared by all adapters
- 5 runtime adapter packages: `@oxdeai/langgraph`, `@oxdeai/openai-agents`, `@oxdeai/crewai`, `@oxdeai/autogen`, `@oxdeai/openclaw`
- all 5 adapter examples migrated to use adapter packages
- integration documentation for all maintained adapters
- cross-adapter validation (`node scripts/validate-adapters.mjs`)
- production-oriented demos and case studies

Note: OxDeAI remains a protocol/enforcement layer, not a framework.

Release notes: [`docs/adapter-stack-release-notes.md`](./docs/adapter-stack-release-notes.md)

Execution checklist:
- [x] Ship 3 maintained adapter targets (`OpenAI Agents SDK`, `CrewAI`, `AutoGen`).
- [x] Ship OpenClaw adapter demo coverage (`examples/openclaw`).
- [x] Define one shared adapter contract (proposed action input, authorization gate, execute/refuse output, audit emission).
  - canonical doc: [`docs/adapter-contract.md`](./docs/adapter-contract.md)
- [x] Document a shared adapter/normalization contract:
  - recommended minimal fields for proposed-action -> intent mapping
  - deterministic normalization expectations across action surfaces
  - cross-adapter reproducibility and comparable audit evidence requirements
- [x] Document how future authorization semantics remain state-modeled in the current contract:
  - context-aware authorization through deterministic state inputs
  - execution path policy modeling through state-carried history or flags
  - delegated authority as a future protocol area with current state-scoped implementation guidance
- [x] Publish a consistent integration kit for each adapter:
  - canonical docs: [`docs/integrations/`](./docs/integrations)
  - install
  - minimal quickstart
  - production PEP wiring notes
- [x] Provide cross-adapter reproducible demo scenario:
  - `ALLOW`, `ALLOW`, `DENY`
  - `verifyEnvelope() => ok`
  - canonical doc: [`docs/integrations/shared-demo-scenario.md`](./docs/integrations/shared-demo-scenario.md)
- [x] Add adapter validation gates in CI/docs:
  - deterministic behavior checks
  - authorization boundary enforcement checks
  - canonical doc: [`docs/integrations/adapter-validation.md`](./docs/integrations/adapter-validation.md)
- [x] Publish at least 2 case-style integration writeups:
  - API cost containment
  - infrastructure provisioning control
  - each writeup includes architecture, controls, failure mode prevented, and verification evidence (snapshot/audit/envelope outcomes)
  - index: [`docs/cases/README.md`](./docs/cases/README.md)

Completion criteria:
- [x] At least 3 adapter integrations are reproducible from docs.
  - reference docs: [`docs/integrations/README.md`](./docs/integrations/README.md)
- [x] Adapter demos are conformance-aligned and produce deterministic verification outcomes.
  - validation docs: [`docs/integrations/adapter-validation.md`](./docs/integrations/adapter-validation.md)
- [x] Integration docs and case studies are sufficient for third-party adoption without source deep-dive.
  - adoption checklist: [`docs/integrations/adoption-checklist.md`](./docs/integrations/adoption-checklist.md)

### v1.5 - Developer Experience
Status: `Done`

Focus:
- visual demos of the authorization boundary
- improved quickstart experience
- architecture explainer for integrators
- clearer adapter integration docs

Execution:
- [x] Add demo GIFs to README
- [x] Improve Quickstart section
- [x] Publish architecture explainer
- [x] Add cross-links between protocol, integrations, and cases
- [x] Ensure demos run in <2 minutes

Completion criteria:
- [x] A new developer can run a demo in under 5 minutes
- [x] The authorization boundary is visually understandable
- [x] Integrations can be reproduced from documentation

References:
- [`docs/media/README.md`](./docs/media/README.md)
- [`docs/architecture/why-oxdeai.md`](./docs/architecture/why-oxdeai.md)

### v2.x - Delegated Agent Authorization
Status: `Planned`

Scope:
- bounded delegation for multi-agent systems
- parent agent can delegate reduced authority to child agents
- delegated authority remains bounded by parent authorization constraints

Possible future artifact:
- `DelegatedAuthorizationV1`

Design preparation:
- [`docs/design/delegated-authorization.md`](./docs/design/delegated-authorization.md)

#### Advanced Authorization Semantics

Future exploration areas:

- context-aware policy evaluation patterns
- execution path policy modeling
- delegated authorization primitives
- safe multi-agent authority propagation

These evolutions preserve the core protocol contract:

`(intent, state, policy) -> deterministic decision`

They MUST avoid introducing non-deterministic evaluation behavior.

### v3.x - Verifiable Execution Infrastructure
Status: `Planned`

Scope:
- deterministic execution receipts
- binary Merkle batching of receipt hashes
- proof-of-inclusion for individual receipts
- optional on-chain proof anchoring / smart-contract verifier

Constraint:
- authorization remains off-chain-first
- on-chain integration is optional proof anchoring, not the core execution flow
