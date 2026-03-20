# OxDeAI

A deterministic execution authorization protocol for AI agents.

Before an agent executes an external action (API call, cloud provisioning, payment, tool invocation), OxDeAI evaluates whether that action is allowed under the current policy state. If denied, the action never executes. If allowed, it emits a cryptographically verifiable `AuthorizationV1` artifact that the enforcement point must verify before any side effect occurs.

> Control execution, not just behavior.

If you are building agents that execute real actions, this layer becomes necessary quickly.

---

## TL;DR

Agents propose actions. OxDeAI decides if they execute. No valid authorization, no execution.

```text
agent proposes action
  → OxDeAI evaluates (intent, state, policy)
  → ALLOW: emits AuthorizationV1 → PEP verifies → execution
  → DENY:  blocked before any side effect
```

---

## What This Looks Like

```bash
pnpm -C examples/openclaw start
```

```
[1] ALLOW  provision_gpu  budget=320/1000
[2] ALLOW  query_db       budget=640/1000
[3] DENY   provision_gpu  BUDGET_EXCEEDED
verifyEnvelope() => ok
```

Two actions authorized. Third refused before execution. Evidence packaged and verified offline.

---

## Try It in 2 Minutes

```bash
git clone https://github.com/AngeYobo/oxdeai.git
cd oxdeai && pnpm install && pnpm build
pnpm -C examples/openclaw start
```

```
ALLOW  provision_gpu  budget=320/1000
ALLOW  query_db       budget=640/1000
DENY   provision_gpu  BUDGET_EXCEEDED
```

No config changes needed. Swap in `examples/langgraph`, `examples/crewai`, or any other adapter for the same output.

---

## Why Devs Care

- **Prevents unintended side effects**: execution is gated on policy, not model output
- **Makes decisions reproducible**: same `(intent, state)` always produces the same decision, across runtimes
- **Works across agent frameworks**: LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, OpenClaw all share one enforcement layer

---

## When You Need This

- An agent makes external API calls, provisions infrastructure, or triggers payments
- You need spend limits, velocity caps, or tool restrictions enforced before execution
- A multi-agent pipeline delegates authority from an orchestrator to worker agents
- You need to prove what an agent was authorized to do, not just what it did
- Concurrent agents share policy state and must not corrupt each other's evaluation
- You need the same authorization semantics across multiple frameworks or runtimes

---

## Failure Modes This Prevents

- **Unintended side effects**: a model output reaches an external system before policy is checked
- **Budget overruns**: an agent keeps spending after limits are reached because the check was post-execution
- **Stale state execution**: a concurrent agent evaluates against already-mutated shared state
- **Permission leakage**: a child agent inherits broader authority than the parent intended to grant
- **Replay and duplicate actions**: the same authorized action executes twice because `auth_id` was not consumed
- **Silent failures**: a DENY produces no artifact, leaving operators nothing to verify or audit

---

## What Makes This Different

| Approach | When it acts | Guarantee |
|---|---|---|
| Prompt guardrails | Before model output | Probabilistic - shapes behavior, does not block execution |
| Monitoring / observability | After execution | Records what happened, cannot undo side effects |
| Sandboxing | At environment level | Isolates process, does not authorize individual actions |
| **OxDeAI** | **Before execution** | **Deterministic - side effect is blocked or explicitly authorized** |

Logs explain what happened. Authorization artifacts prove what was allowed.

---

## What OxDeAI Is

- A deterministic execution authorization protocol for autonomous systems
- Pre-execution authorization: no side effect without a verified `AuthorizationV1` artifact
- Fail-closed execution gating: `ALLOW` without a valid artifact throws `OxDeAIAuthorizationError`
- Tamper-evident audit chains and offline-verifiable evidence via `VerificationEnvelopeV1`

## What OxDeAI Is Not

- A billing system, metering pipeline, or pricing proxy
- A prompt guardrail or output filter
- A runtime or orchestration engine

OxDeAI can enforce spend, velocity, concurrency, replay, and capability policies, but its core role is execution authorization, not downstream accounting.

---

## Why OxDeAI Exists

Prompt guardrails, output filters, and observability all operate outside the execution path. They are probabilistic (p < 1): they reduce risk but cannot guarantee a side effect is blocked.

OxDeAI enforces a deterministic boundary (p = 1): execution either passes the policy gate or it does not.

```text
Prompt guardrails     →  shape model behavior     →  p < 1
Execution authorization  →  gate the side effect  →  p = 1
```

> Logs are narratives. Authorization artifacts are proofs.

The critical question is deterministic: **is this action allowed to execute under the current policy state?** OxDeAI answers it with a signed, verifiable artifact, before any side effect occurs.


---

## Correctness Guarantees

- **Deterministic evaluation**: `(intent, state, policy) → decision` is pure and side-effect-free; same inputs always produce the same result
- **Fail-closed execution**: no execution path bypasses the authorization gate; missing or invalid artifact throws immediately
- **Evaluation isolation**: each evaluation receives a `structuredClone` of shared state; concurrent calls cannot corrupt each other's policy context (invariant I6)
- **Cross-adapter equivalence**: identical normalized intent + identical policy state produces identical decisions across all maintained adapters (validated by `@oxdeai/compat`, CA-1–CA-10)

Covered by 139 frozen conformance assertions (`pnpm -C packages/conformance validate`) and property-based tests (D-P1–D-P5, G-D1–G-D3) across core and guard. DelegationV1 cases include independent Ed25519 verification in Go and Python harnesses.

---

## Validation

Behavior is defined by frozen conformance vectors, not just the reference implementation.

- **139 conformance assertions** across intent hashing, authorization, snapshot, audit chain, envelope, and DelegationV1 verification
- **Cross-adapter validation**: `node scripts/validate-adapters.mjs` confirms identical protocol outcomes across all 6 maintained adapters
- **Property-based tests**: D-P1 through D-P5 (delegation scope/hash invariants), G-D1 through G-D3 (guard enforcement), CA-1 through CA-10 (cross-adapter equivalence)
- **Multi-language harness**: Go harness + Python adapter independently verify all vector sets, including Ed25519 signature verification for DelegationV1 without oracle/lookup fallback
- **Frozen vector policy**: vectors are immutable per protocol version; any behavior change requires a new versioned baseline

References: [`packages/conformance`](./packages/conformance) · [`docs/conformance-vectors.md`](./docs/conformance-vectors.md) · [`docs/invariants.md`](./docs/invariants.md) · [`SPEC.md`](./SPEC.md)

---

## Artifact-First Model

OxDeAI does not rely on a control plane at execution time.

Every allowed action produces a portable `AuthorizationV1` artifact.

The executor verifies:

- signature
- intent binding
- state binding
- policy binding

Execution happens only if verification succeeds.

---

## Protocol Model

OxDeAI follows a standard PDP/PEP architecture:

- **PDP** (Policy Decision Point): evaluates `(intent, state)` → decision
- **PEP** (Policy Enforcement Point): verifies `AuthorizationV1` or `DelegationV1` → executes or denies

The PEP MUST NOT execute without a valid authorization artifact.

Authorization artifacts:

| Artifact | Issued by | Scope |
|---|---|---|
| `AuthorizationV1` | PDP (policy evaluation) | defined by policy |
| `DelegationV1` | delegating principal | subset of parent `AuthorizationV1` |

---

## Protocol Status

| Artifact | Status | Notes |
|---|---|---|
| `AuthorizationV1` | Stable | Ed25519-signed, fully conformance-backed, cross-language verified |
| `DelegationV1` | Stable | Ed25519-signed, conformance-backed, independent harness verification |
| `VerificationEnvelopeV1` | Stable | Snapshot + audit chain, offline verifiable |
| `ExecutionReceiptV1` | Planned | Deterministic execution receipts, Merkle batching (v3.x) |

Protocol spec: [`SPEC.md`](./SPEC.md) · Invariants: [`docs/invariants.md`](./docs/invariants.md) · Conformance: [`packages/conformance`](./packages/conformance)

---

## How It Works

1. A runtime proposes an action.
2. OxDeAI canonicalizes and evaluates `(intent, state)` deterministically.
3. If policy allows execution, OxDeAI emits an `AuthorizationV1` artifact.
4. The policy enforcement point executes only when a valid authorization artifact is present.
5. If policy denies the action, execution is blocked before any side effect occurs.
6. Post-execution evidence can be packaged into a `VerificationEnvelopeV1` for offline verification.

---

## Delegated Authorization

A principal holding a valid `AuthorizationV1` can delegate a strictly narrowed subset of that authority to a child agent using `DelegationV1`.

```
parent-agent  →  AuthorizationV1   (tools=[provision_gpu, query_db], budget=1000)
                      ↓ creates
                 DelegationV1      (tools=[provision_gpu], max_amount=300, expiry=60s)
                      ↓ presented by
child-agent   →  PEP verifyDelegation()
                      ↓
                 Execution (within child scope only)
```

Key properties:

- **Strictly narrowing** - scope, amount, and expiry can only be reduced, never expanded
- **Single-hop** - a `DelegationV1` cannot itself be re-delegated
- **Locally verifiable** - no control plane required at execution time
- **Cryptographically bound** - Ed25519-signed, tied to a specific parent `AuthorizationV1` by hash


```typescript
import { createDelegation, verifyDelegation } from "@oxdeai/core";

// Parent creates a delegation for child-agent
const delegation = createDelegation(parentAuth, {
  delegatee: "child-agent",
  scope: { tools: ["provision_gpu"], max_amount: 300 },
  expiry: Date.now() + 60_000,
  kid: "key-1",
}, privateKeyPem);

// Child PEP verifies before execution
const result = verifyDelegation(delegation, parentAuth, {
  trustedKeySets: [keyset],
  now: Date.now(),
});
// result.ok === true → execute
// result.ok === false → DENY, tool blocked
```

Demo: [`examples/delegation`](./examples/delegation)
Spec: [`docs/spec/delegation-v1.md`](./docs/spec/delegation-v1.md)

---

## Comparison

| System | Controls |
|---|---|
| Prompt guardrails | model behavior (probabilistic) |
| Observability | logs after execution |
| Sandboxing | environment isolation |
| OxDeAI | execution authorization (deterministic) |

---

## Quick Demo

This is the minimal reproducible scenario.

![OxDeAI demo](docs/media/oxdeai-demo.gif)

```bash
pnpm -C examples/openclaw start
```

Expected result:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Two proposed actions are authorized, the third is refused before execution, and the resulting verification evidence can be checked offline.

---

## Key Properties

- Deterministic policy evaluation - same `(intent, state)` always produces the same decision
- Pre-execution authorization - no side effect without a valid `AuthorizationV1` artifact
- Cryptographic authorization artifacts - Ed25519-signed, non-forgeable
- Fail-closed execution gating - `ALLOW` without a valid artifact throws `OxDeAIAuthorizationError`
- Tamper-evident audit chains - hash-chained events, stateless verifiability
- Offline verifiable evidence - snapshot + audit chain packaged as a `verificationEnvelope`

---

## Adapter Stack

`@oxdeai/guard` centralizes the universal PEP security boundary. Runtime adapters are thin bindings - none contain authorization logic. Adopting a new runtime requires only a thin adapter, not a new authorization implementation.

This keeps the protocol surface stable while allowing multiple runtimes to integrate the same execution authorization boundary.

| Package | Role | Example |
|---|---|---|
| `@oxdeai/guard` | Universal execution guard (PEP) | - |
| `@oxdeai/langgraph` | LangGraph binding | [`examples/langgraph`](./examples/langgraph) |
| `@oxdeai/openai-agents` | OpenAI Agents SDK binding | [`examples/openai-agents-sdk`](./examples/openai-agents-sdk) |
| `@oxdeai/crewai` | CrewAI binding | [`examples/crewai`](./examples/crewai) |
| `@oxdeai/autogen` | AutoGen binding | [`examples/autogen`](./examples/autogen) |
| `@oxdeai/openclaw` | OpenClaw binding | [`examples/openclaw`](./examples/openclaw) |

All maintained adapters implement the same reproducible authorization scenario (`ALLOW` / `ALLOW` / `DENY` / `verifyEnvelope() => ok`):

![Cross-adapter demo](docs/media/oxdeai-demo-cross-adapter.gif)

References:
- [Adapter stack architecture](./docs/integrations/adapter-stack.md)
- [Adapter reference architecture](./docs/adapter-reference-architecture.md)
- [Adapter release notes](./docs/adapter-stack-release-notes.md)
- [Shared demo scenario](./docs/integrations/shared-demo-scenario.md)

---

## Authorization Policy Domains

- **Spend authorization** - enforce per-action and cumulative spend limits before execution ([case study](./docs/cases/api-cost-containment.md))
- **Infrastructure authorization** - gate GPU allocation, cloud resource creation, and database operations ([case study](./docs/cases/infrastructure-provisioning-control.md))
- **Workflow authorization** - deterministic authorization gates for multi-step agent pipelines
- **Bounded execution policies** - velocity limits, concurrency caps, replay protection, and kill-switch enforcement

---

## Benchmarks

OxDeAI adds a deterministic authorization boundary with bounded inline overhead.

On the tested machine (latest full-suite run, `bench/outputs/run-2026-03-11-12-25-55.json`):

| Mode | p50 overhead | mean overhead |
|---|---|---|
| `best-effort` | +14.8 µs | +21.8 µs |
| `strict` | +16.6 µs | +25.2 µs |

Overhead measured as `protectedPath - baselinePath` on a single worker. Results depend on hardware, runtime, and workload.

Full benchmark methodology: [`bench/README.md`](./bench/README.md) · Run write-up: [`bench/BENCHMARK_SUMMARY.md`](./bench/BENCHMARK_SUMMARY.md) · Announcement: [`docs/benchmark-announcement.md`](./docs/benchmark-announcement.md)

---

## Validation Snapshot

Latest local validation (2026-03-20):

- `pnpm build` - pass
- `pnpm -C packages/conformance validate` - pass (139 assertions)
- `pnpm -r test` - pass (all adapter tests pass)
- `node scripts/validate-adapters.mjs` - pass (6/6 adapters)
- `pnpm -C examples/openai-tools start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/langgraph start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/crewai start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/openai-agents-sdk start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/autogen start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/openclaw start` - `ALLOW`, `ALLOW`, `DENY`, envelope `ok`
- `pnpm -C examples/delegation start` - `ALLOW`, `ALLOW`, `DENY`, `DENY`

DelegationV1 conformance vectors include independent Ed25519 verification in Go and Python harnesses, with no oracle/lookup pattern.

Adapter validation references: [adapter-validation.md](./docs/integrations/adapter-validation.md) · [adoption-checklist.md](./docs/integrations/adoption-checklist.md)

Protocol invariants are mapped to implementation tests and property-based coverage in [docs/invariants.md](./docs/invariants.md).

Cross-adapter behavior is validated at boundary conditions, replay protection, and concurrency isolation.

---

OxDeAI is designed as a protocol with a reference implementation: runtimes propose actions, policy decides deterministically, and relying parties verify authorization artifacts before execution.

## Quickstart

Runs in under 2 minutes.

### Requirements

- Node.js >= 20
- pnpm >= 9

```bash
git clone https://github.com/AngeYobo/oxdeai.git
cd oxdeai
corepack enable && corepack prepare pnpm@9.12.2 --activate
pnpm install
pnpm build
pnpm -C examples/openai-tools start
```

### Core concept

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";

const guard = OxDeAIGuard({ engine, getState, setState });

// execute is only called when the action is authorized
const result = await guard(proposedAction, async () => {
  return executeAction(); // never reached on DENY
});
```

For runtime-specific bindings:

```typescript
import { createLangGraphGuard } from "@oxdeai/langgraph";
// or: createCrewAIGuard, createOpenAIAgentsGuard, createAutoGenGuard, createOpenClawGuard

const guard = createLangGraphGuard({ engine, getState, setState, agentId: "my-agent" });

const result = await guard(
  { name: "provision_gpu", args: { asset: "a100" }, id: "call-1" },
  async () => provisionGpu("a100")
);
```

On `DENY`, `OxDeAIDenyError` is thrown and the callback is never called.

---

## Repo Layout

Protocol packages:
- [`packages/core`](./packages/core) - protocol reference implementation (`PolicyEngine`, `AuthorizationV1`, audit chain, snapshot, envelope)
- [`packages/sdk`](./packages/sdk) - integration helpers: intent builders, state builders, conformance utilities
- [`packages/conformance`](./packages/conformance) - frozen test vectors and compatibility validator

PEP enforcement:
- [`packages/guard`](./packages/guard) - universal execution guard; all authorization logic lives here

Runtime adapter packages:
- [`packages/langgraph`](./packages/langgraph) - thin LangGraph binding
- [`packages/openai-agents`](./packages/openai-agents) - thin OpenAI Agents SDK binding
- [`packages/crewai`](./packages/crewai) - thin CrewAI binding
- [`packages/autogen`](./packages/autogen) - thin AutoGen binding
- [`packages/openclaw`](./packages/openclaw) - thin OpenClaw binding

Tooling:
- [`packages/cli`](./packages/cli) - protocol-oriented local tooling (`build`, `verify`, `replay`)

Specs and docs:
- `SPEC.md`, `SECURITY.md`, `PROTOCOL.md`
- Architecture: [`docs/architecture.md`](./docs/architecture.md) · [Why OxDeAI](./docs/architecture/why-oxdeai.md)
- Integrations: [`docs/integrations/README.md`](./docs/integrations/README.md)
- Production wiring: [`docs/pep-production-guide.md`](./docs/pep-production-guide.md)
- Multi-language: [`docs/multi-language.md`](./docs/multi-language.md)

---

## Ecosystem Positioning

OxDeAI operates at the execution authorization layer.

A useful way to think about the stack:

- Layer 1: prompt and model safety
- Layer 2: runtime orchestration and observability
- Layer 3: execution authorization and relying-party enforcement

Most agent safety systems focus on what models say or what runtimes log. OxDeAI focuses on what agents are actually allowed to execute.

![Agent safety layers](./docs/diagrams/agent-safety-layers.svg)

---

## Multi-Language

TypeScript is the current reference implementation.

OxDeAI artifacts are portable protocol artifacts: Rust, Go, and Python developers can verify `AuthorizationV1`, snapshots, audit chains, and verification envelopes today without reusing the TypeScript runtime itself.

- [`docs/multi-language.md`](./docs/multi-language.md)
- [`docs/conformance-vectors.md`](./docs/conformance-vectors.md)

---

## Release and Roadmap

| Milestone | Status |
|---|---|
| `v1.1` Authorization Artifact | complete |
| `v1.2` Non-Forgeable Verification | complete |
| `v1.3` Guard Adapter + Integration Surface | complete |
| `v1.4` Ecosystem Adoption | complete |
| `v1.5` Developer Experience | complete |
| `v2.x` Delegated Agent Authorization | complete |
| `v3.x` Verifiable Execution Infrastructure | planned |

### v1.4 - Ecosystem Adoption

Delivered the universal adapter layer:

- `@oxdeai/guard` - single PEP package shared by all adapters
- 5 runtime adapter packages: `@oxdeai/langgraph`, `@oxdeai/openai-agents`, `@oxdeai/crewai`, `@oxdeai/autogen`, `@oxdeai/openclaw`
- all adapter examples migrated to use adapter packages
- integration documentation for all maintained adapters: [`docs/integrations/`](./docs/integrations/)
- cross-adapter validation: `node scripts/validate-adapters.mjs`
- shared adapter contract: [`docs/adapter-contract.md`](./docs/adapter-contract.md)
- shared demo scenario (`ALLOW` / `ALLOW` / `DENY` / `verifyEnvelope() => ok`): [`docs/integrations/shared-demo-scenario.md`](./docs/integrations/shared-demo-scenario.md)
- case studies: [API cost containment](./docs/cases/api-cost-containment.md) · [infrastructure provisioning control](./docs/cases/infrastructure-provisioning-control.md)
- release notes: [`docs/adapter-stack-release-notes.md`](./docs/adapter-stack-release-notes.md)

### v1.5 - Developer Experience

Delivered integrator-facing clarity:

- demo GIFs added to README
- quickstart improved
- architecture explainer published: [`docs/architecture/why-oxdeai.md`](./docs/architecture/why-oxdeai.md)
- cross-links between protocol, integrations, and cases
- demos run in under 2 minutes

Full roadmap: [`ROADMAP.md`](./ROADMAP.md) · Release policy: [`RELEASE.md`](./RELEASE.md) · Release checklist: [`docs/release-checklist.md`](./docs/release-checklist.md)

### Version

Protocol stack: `@oxdeai/core` `1.6.0` · `@oxdeai/sdk` `1.3.1` · `@oxdeai/conformance` `1.4.0`

Adapter packages: `@oxdeai/guard` `1.0.2` · `@oxdeai/langgraph` `1.0.1` · `@oxdeai/openai-agents` `1.0.1` · `@oxdeai/crewai` `1.0.1` · `@oxdeai/autogen` `1.0.1` · `@oxdeai/openclaw` `1.0.1`

Tooling: `@oxdeai/cli` `0.2.4`

---

## Contributing

- [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- [`SECURITY.md`](./SECURITY.md)
- [Integrations index](./docs/integrations/README.md)
- [Adapter reference architecture](./docs/adapter-reference-architecture.md)
- [Conformance vectors](./packages/conformance)
