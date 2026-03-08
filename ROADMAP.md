# OxDeAI Roadmap Status

Last updated: 2026-03-08

## Version Snapshot

Protocol stack:
- `@oxdeai/core`: `1.3.0`
- `@oxdeai/sdk`: `1.3.1`
- `@oxdeai/conformance`: `1.3.1`

Tooling:
- `@oxdeai/cli`: `0.2.2` (independent tooling line)

## Current Validation Snapshot

- [x] `pnpm build` passes
- [x] `pnpm -r test` passes
- [x] `pnpm -C packages/conformance validate` passes (`94` assertions)
- [x] `examples/openai-tools` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/langgraph` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)

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
Status: `Next`

Focus:
- more framework adapters
- integration documentation
- production-oriented demos
- case-study style examples

Examples of target integrations:
- CrewAI
- OpenAI Agents SDK
- AutoGen
- OpenClaw
- other runtime adapters

Note: OxDeAI remains a protocol/enforcement layer, not a framework.
OpenClaw status: demo integration is implemented; broader production/runtime-specific integration remains future work.

Execution checklist:
- [x] Ship 3 maintained adapter targets (`OpenAI Agents SDK`, `CrewAI`, `AutoGen`).
- [x] Ship OpenClaw adapter demo coverage (`examples/openclaw`).
- [ ] Define one shared adapter contract (proposed action input, authorization gate, execute/refuse output, audit emission).
- [ ] Publish a consistent integration kit for each adapter:
  - install
  - minimal quickstart
  - production PEP wiring notes
- [ ] Provide cross-adapter reproducible demo scenario:
  - `ALLOW`, `ALLOW`, `DENY`
  - `verifyEnvelope() => ok`
- [ ] Add adapter validation gates in CI/docs:
  - deterministic behavior checks
  - authorization boundary enforcement checks
- [ ] Publish at least 2 case-style integration writeups:
  - API cost containment
  - infrastructure provisioning control
  - each writeup includes architecture, controls, failure mode prevented, and verification evidence (snapshot/audit/envelope outcomes)

Completion criteria:
- [ ] At least 3 adapter integrations are reproducible from docs.
- [ ] Adapter demos are conformance-aligned and produce deterministic verification outcomes.
- [ ] Integration docs and case studies are sufficient for third-party adoption without source deep-dive.

### v2.x - Delegated Agent Authorization
Status: `Planned`

Scope:
- bounded delegation for multi-agent systems
- parent agent can delegate reduced authority to child agents
- delegated authority remains bounded by parent authorization constraints

Possible future artifact:
- `DelegatedAuthorizationV1`

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
