# OxDeAI Roadmap Status

Last updated: 2026-03-20

## Version Snapshot

Protocol stack:
- `@oxdeai/core`: `1.6.0`
- `@oxdeai/sdk`: `1.3.1`
- `@oxdeai/conformance`: `1.4.0`

Adapter packages:
- `@oxdeai/guard`: `1.0.2`
- `@oxdeai/langgraph`, `@oxdeai/openai-agents`, `@oxdeai/crewai`, `@oxdeai/autogen`, `@oxdeai/openclaw`: `1.0.1`

Tooling:
- `@oxdeai/cli`: `0.2.4` (independent tooling line)

## Current Validation Snapshot

- [x] `pnpm build` passes
- [x] `pnpm -r test` passes (all adapter tests)
- [x] `pnpm -C packages/conformance validate` passes (`139` assertions)
- [x] `node scripts/validate-adapters.mjs` passes (6/6 adapters)
- [x] `examples/openai-tools` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/langgraph` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/crewai` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/openai-agents-sdk` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/autogen` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/openclaw` passes (`ALLOW`, `ALLOW`, `DENY`, `verifyEnvelope() => ok`)
- [x] `examples/delegation` passes (`ALLOW`, `ALLOW`, `DENY`, `DENY`)

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
Status: `Done`

Delivered:
- `DelegationV1` as a first-class protocol artifact (`SPEC.md` v1.3.0, Section 5)
- `createDelegation()`, `verifyDelegation()`, `verifyDelegationChain()` in `@oxdeai/core`
- strictly narrowing scope enforcement: `tools`, `max_amount`, `max_actions`, `max_depth`
- single-hop constraint - `DelegationV1` cannot be re-delegated
- local chain verification at the PEP - no control-plane call required
- guard integration (`@oxdeai/guard`) - fail-closed, `setState` skipped on delegation path
- full delegation test matrix - 9 cases across core + guard, including determinism checks
- `examples/delegation` - end-to-end demo using `@oxdeai/core`, produces `ALLOW`, `ALLOW`, `DENY`, `DENY`
- frozen conformance vectors for `DelegationV1`: parent-hash, verification, chain, signature (139 assertions)
- Go harness + Python adapter with independent Ed25519 verification - no lookup oracle for chain/sig cases
- `delegation_parent_hash`, `verify_delegation`, `verify_delegation_chain`, `verify_delegation_signature` adapter ops

Out of scope for this release:
- multi-hop delegation (chaining `DelegationV1` from `DelegationV1`)
- federation (delegating authority across organizational trust boundaries)
- cross-org trust discovery
- revocation mesh

References:
- Protocol spec: [`SPEC.md §5`](./SPEC.md)
- Artifact spec: [`docs/spec/delegation-v1.md`](./docs/spec/delegation-v1.md)
- Demo: [`examples/delegation`](./examples/delegation)

### v2.5 - Adoption & Execution Pressure
Status: `Planned`

This phase turns OxDeAI from a protocol and reference implementation into a production-adoptable execution control layer. 
The focus is not new core semantics, it is making OxDeAI easier to try, integrate, pressure-test, and compare against real agent failure modes.

Scope:
- production failure playbooks mapping real failure modes to OxDeAI mitigations
- drop-in guard integration paths for all maintained adapters
- opinionated policy presets for common execution constraints
- failure demos showing agent behavior without boundary vs. with OxDeAI enforcing it
- lightweight structured event hooks around authorization decisions (ALLOW / DENY / VERIFY)
- adoption pressure testing across maintained adapters under realistic execution patterns

Focus:
- publish concrete case studies:
  - API budget exhaustion
  - unintended tool chaining
  - stale state execution
  - permission leakage across delegated agents
- first successful integration achievable in under 5 minutes from docs
- reusable policy presets for common controls:
  - budget limits
  - tool allowlists
  - replay protection
  - concurrency limits
- one "break your agent" failure demo: no boundary vs. OxDeAI hard stop, reproducible from docs
- structured decision events documented and consumable by external tooling without requiring a full observability platform

Not the goal of v2.5:
- no new core artifact semantics
- no federation
- no multi-hop delegation
- no on-chain execution path
- no full observability platform
- no runtime or orchestration framework expansion

Completion criteria:
- at least 3 production-style failure playbooks published
- all maintained adapters have copy-paste quickstarts
- failure demo reproducible from docs in under 2 minutes
- policy presets exist for common execution controls
- structured decision events documented and consumable by external tooling
- at least one external builder can adopt OxDeAI without reading core source deeply

Planned references:
- [`docs/cases/README.md`](./docs/cases/README.md)
- [`docs/cases/api-budget-exhaustion.md`](./docs/cases/api-budget-exhaustion.md)
- [`docs/cases/unintended-tool-chaining.md`](./docs/cases/unintended-tool-chaining.md)
- [`docs/cases/stale-state-execution.md`](./docs/cases/stale-state-execution.md)
- [`docs/integrations/`](./docs/integrations/)
- [`docs/presets/`](./docs/presets/)
- [`examples/failure-demo`](./examples/failure-demo)
- [`docs/observability-hooks.md`](./docs/observability-hooks.md)

---

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
