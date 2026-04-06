# OxDeAI Roadmap Status

**Last updated:** 2026-04-05

---

## Version Snapshot

### Protocol stack

* `@oxdeai/core`: `1.7.0`
* `@oxdeai/sdk`: `1.3.2`
* `@oxdeai/conformance`: `1.5.0`

### Adapter packages

* `@oxdeai/guard`: `1.0.2`
* `@oxdeai/langgraph`: `1.0.1`
* `@oxdeai/openai-agents`: `1.0.1`
* `@oxdeai/crewai`: `1.0.1`
* `@oxdeai/autogen`: `1.0.1`
* `@oxdeai/openclaw`: `1.0.1`

### Tooling

* `@oxdeai/cli`: `0.2.4`
  Independent tooling line

---

## Current Validation Snapshot

### Build and test status

* `pnpm build` passes
* `pnpm -r test` passes
* `pnpm -C packages/conformance validate` passes (`139 assertions`)
* `node scripts/validate-adapters.mjs` passes (`6/6 adapters`)
* `pnpm test:vectors:all` passes

### Vector and protocol validation

* Canonicalization vectors pass (`TypeScript / Go / Python`)
* `AuthorizationV1` vectors pass
* PEP gateway vectors pass
* `DelegationV1` vectors pass

### Example validation

* `examples/openai-tools` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/langgraph` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/crewai` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/openai-agents-sdk` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/autogen` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/openclaw` passes
  `ALLOW, ALLOW, DENY, verifyEnvelope() => ok`
* `examples/delegation` passes
  `ALLOW, ALLOW, DENY, DENY`
* Non-bypassable execution demo passes
  `ALLOW, DENY_HASH_MISMATCH, REPLAY, BYPASS`

---

## Architecture Doctrine

OxDeAI is optimized for:

* deterministic execution authorization
* framework-agnostic integration
* authorization-boundary enforcement
* fail-closed execution control before side effects

OxDeAI is not:

* a replacement runtime
* a full agent framework
* a prompt/output guardrail layer
* an on-chain-first platform

---

## Milestones

---

### v1.1 — Authorization Artifact

**Status:** Done

#### Delivered

* `AuthorizationV1` as a first-class protocol artifact
* relying-party / PEP verification contract
* first-class authorization semantics for pre-execution gating

---

### v1.2 — Non-Forgeable Verification

**Status:** Done

#### Delivered

* Ed25519 signature support
* required `alg` / `kid` / `signature` metadata path
* public-key verification primitives
* `KeySet` model for issuer/key selection and rotation windows
* conformance validation coverage for signature and key-failure paths

---

### v1.3 — Guard Adapter + Integration Surface

**Status:** Done

#### Delivered

* stable SDK guard/integration surface
* OpenAI tools reference boundary demo
* LangGraph integration demo
* production PEP wiring guide
* deterministic envelope verification across demos

#### References

* `examples/openai-tools`
* `examples/langgraph`
* `examples/crewai`
* `examples/openai-agents-sdk`
* `examples/autogen`
* `examples/openclaw`
* `docs/pep-production-guide.md`

---

### v1.4 — Ecosystem Adoption

**Status:** Done

#### Delivered

* universal execution guard (`@oxdeai/guard`)
  Single PEP package shared by all adapters
* 5 runtime adapter packages:

  * `@oxdeai/langgraph`
  * `@oxdeai/openai-agents`
  * `@oxdeai/crewai`
  * `@oxdeai/autogen`
  * `@oxdeai/openclaw`
* all 5 adapter examples migrated to use adapter packages
* integration documentation for all maintained adapters
* cross-adapter validation (`node scripts/validate-adapters.mjs`)
* production-oriented demos and case studies

**Note:** OxDeAI remains a protocol/enforcement layer, not a framework.

#### Release notes

* `docs/adapter-stack-release-notes.md`

#### Execution checklist

* Ship 3 maintained adapter targets
  (`OpenAI Agents SDK`, `CrewAI`, `AutoGen`)
* Ship OpenClaw adapter demo coverage (`examples/openclaw`)
* Define one shared adapter contract:

  * proposed action input
  * authorization gate
  * execute/refuse output
  * audit emission
* Document deterministic normalization expectations across action surfaces
* Publish integration kits for maintained adapters
* Provide cross-adapter reproducible demo scenario
* Add adapter validation gates in CI/docs
* Publish case-style integration writeups

#### Completion criteria

* At least 3 adapter integrations are reproducible from docs
* Adapter demos are conformance-aligned and produce deterministic verification outcomes
* Integration docs and case studies are sufficient for third-party adoption without source deep-dive

---

### v1.5 — Developer Experience

**Status:** Done

#### Focus

* visual demos of the authorization boundary
* improved quickstart experience
* architecture explainer for integrators
* clearer adapter integration docs

#### Execution

* Add demo GIFs to README
* Improve Quickstart section
* Publish architecture explainer
* Add cross-links between protocol, integrations, and cases
* Ensure demos run in under 2 minutes
* Add non-bypassable split-screen GIF demo
* Expose spec / proof / enforcement clearly in README

#### Completion criteria

* A new developer can run a demo in under 5 minutes
* The authorization boundary is visually understandable
* Integrations can be reproduced from documentation

#### References

* `docs/media/README.md`
* `docs/architecture/why-oxdeai.md`
* `docs/media/non-bypassable-split.gif`

---

### v2.x — Delegated Agent Authorization

**Status:** Done

#### Delivered

* `DelegationV1` as a first-class protocol artifact (`SPEC.md v1.3.0`, Section 5)
* `createDelegation()`, `verifyDelegation()`, `verifyDelegationChain()` in `@oxdeai/core`
* strictly narrowing scope enforcement:

  * tools
  * `max_amount`
  * `max_actions`
  * `max_depth`
* single-hop constraint
  `DelegationV1` cannot be re-delegated
* local chain verification at the PEP
  No control-plane call required
* guard integration (`@oxdeai/guard`)
  fail-closed, `setState` skipped on delegation path
* full delegation test matrix across core + guard, including determinism checks
* `examples/delegation` end-to-end demo using `@oxdeai/core`
* locked `DelegationV1` conformance vectors
* runnable `DelegationV1` vector verifier
* CI coverage for delegation vectors
* Go harness + Python adapter with independent Ed25519 verification
  No lookup oracle for chain/signature cases

#### Out of scope for this release

* multi-hop delegation
* federation across organizational trust boundaries
* cross-org trust discovery
* revocation mesh

#### References

* `SPEC.md` §5
* `docs/spec/delegation-v1.md`
* `examples/delegation`

---

### v2.5 — ETA Core, Proof, and Infra Boundary

**Status:** In Progress

This phase aligns OxDeAI with an explicit **Execution-Time Authorization (ETA)** core profile and turns the protocol from a strong reference implementation into an adoptable infra primitive.

#### Delivered so far

* `docs/spec/canonicalization-v1.md`
* `docs/spec/authorization-v1.md`
* `docs/spec/eta-core-v1.md`
* `docs/spec/pep-gateway-v1.md`
* `docs/spec/conformance-v1.md`
* `docs/spec/test-vectors-v1.md`
* normative canonicalization rules:

  * deterministic bytes
  * bounds
  * errors
* explicit `AuthorizationV1` artifact spec
* explicit PEP gateway contract
* executable proof coverage across:

  * canonicalization
  * `AuthorizationV1`
  * PEP gateway behavior
  * `DelegationV1`
* cross-language determinism proof (`TypeScript / Go / Python`) for canonicalization
* non-bypassable gateway / protected-upstream demo
* invariant demonstrated publicly:
  `No valid authorization -> no execution path`

#### Remaining scope

* production failure playbooks mapping real failure modes to OxDeAI mitigations
* drop-in enforcement outside the agent runtime
* first infra-native integration package (`HTTP / Express / Fastify` PEP middleware)
* lightweight structured event hooks around authorization decisions
* adoption pressure testing across maintained adapters under realistic execution patterns
* gateway / proxy / sidecar deployment guidance for real infra boundaries
* external-builder-first quickstarts (`< 10 minutes`)

#### Focus

* publish concrete case studies:

  * API budget exhaustion
  * unintended tool chaining
  * stale state execution
  * permission leakage across delegated agents
* demonstrate enforcement at infra boundary, not only SDK
* ensure execution cannot occur without prior authorization verification
* ship one “break your agent” failure demo:

  * no boundary
  * OxDeAI hard stop
* make first successful adoption possible without reading core source

#### Not the goal of v2.5

* no new core artifact semantics
* no federation
* no multi-hop delegation
* no on-chain execution path
* no full observability platform
* no runtime or orchestration framework expansion

#### Completion criteria

* ETA core profile implemented in `docs/spec`
* deterministic outputs verified across environments
* conformance vectors runnable for:

  * canonicalization
  * `AuthorizationV1`
  * PEP
  * `DelegationV1`
* non-bypassable demo proves enforcement boundary
* at least 3 production-style failure playbooks published
* all maintained adapters have copy-paste quickstarts
* first drop-in `HTTP / Express / Fastify` enforcement package shipped
* structured decision events documented and consumable by external tooling
* at least one external builder can adopt OxDeAI without reading core source deeply

#### Planned references

* `docs/spec/canonicalization-v1.md`
* `docs/spec/authorization-v1.md`
* `docs/spec/eta-core-v1.md`
* `docs/spec/pep-gateway-v1.md`
* `docs/spec/conformance-v1.md`
* `docs/cases/README.md`
* `docs/presets/`
* `examples/non-bypassable-demo`
* `docs/observability-hooks.md`

---

### v2.6 — Drop-in Infra Integrations

**Status:** Planned

This phase focuses on making OxDeAI adoptable as a direct execution boundary for side-effecting HTTP actions.

#### Scope

* first-party HTTP PEP package
* Express middleware integration
* Fastify middleware integration
* route-level authorization examples
* relayer / executor boundary examples
* payments-first and infra-provisioning-first reference integrations
* copy-paste quickstarts
* curl-first reproducible demos

#### Candidate deliverables

* `@oxdeai/http-pep` or equivalent package
* Express example:

  * `POST /payments/charge`
  * `AuthorizationV1` verified before handler execution
* Fastify example:

  * `POST /infra/provision-gpu`
  * replay / audience / intent hash enforced
* standard deny response contract for HTTP actions
* reference docs for protecting side-effecting routes

#### Completion criteria

* one drop-in HTTP package shipped
* Express integration reproducible in under 10 minutes
* Fastify integration reproducible in under 10 minutes
* at least one payments demo and one infra demo published
* denial / replay / audience mismatch / intent mismatch demonstrated on real routes

---

### v3.x — Verifiable Execution Infrastructure

**Status:** Planned

#### Scope

* deterministic execution receipts
* verification envelopes (`VerificationEnvelopeV1`) as aggregated execution evidence
* binary Merkle batching of receipt hashes
* proof-of-inclusion for individual receipts
* optional on-chain proof anchoring / smart-contract verifier
* cross-language artifact verification (ETA interoperability)
* canonicalization stability guarantees

#### Constraint

Authorization remains **off-chain-first**.

On-chain integration is optional proof anchoring, not the core execution flow.

---

## Summary

### Done

* `AuthorizationV1`
* Ed25519-backed verification
* guard/adapters
* ecosystem adoption milestone
* developer experience milestone
* delegated authorization
* conformance and cross-language proof
* non-bypassable execution demo

### In progress

* ETA core profile
* infra-native enforcement packaging
* failure playbooks
* external-builder adoption path

### Planned

* drop-in HTTP/Express/Fastify integrations
* verifiable execution receipts and inclusion proofs
