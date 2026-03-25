OxDeAI - Execution Authorization Process

Overview

OxDeAI enforces deterministic authorization at the execution boundary of autonomous systems.

It separates two concerns that are often conflated:
 • Decision: whether an action is allowed
 • Execution: whether that action can actually occur

OxDeAI ensures that:

No side effect is reachable unless explicitly authorized and verified.

⸻

Core Model

At the center of the protocol is a deterministic evaluation:

(intent, state, policy) → ALLOW | DENY

 • intent: the proposed action (tool call, API request, infra operation, etc.)
 • state: current policy state (budgets, concurrency, replay window, etc.)
 • policy: deterministic rules governing allowed behavior

This evaluation is:
 • deterministic
 • side-effect free
 • reproducible across environments

⸻

High-Level Flow

Agent → Propose Action → Policy Evaluation → Authorization → Verification → Execution

Each step is strictly separated and enforced.

⸻

Step-by-Step Process

1. Action Proposal

An agent (LLM, workflow, automation system) proposes an action:
 • call an external API
 • provision infrastructure
 • execute a command
 • trigger a workflow

At this stage:

This is only a proposal, not execution.

⸻

2. Deterministic Policy Evaluation (PDP)

The Policy Engine (PDP) evaluates:

(intent, state, policy)

Output:
 • ALLOW
 • DENY

Properties:
 • no randomness
 • no hidden state
 • no external dependency
 • fail-closed by default

⸻

3. Decision Outcomes

DENY
If the decision is DENY:
 • execution is blocked
 • no side effect occurs
 • an audit event is recorded

DENY → no execution


⸻

ALLOW
If the decision is ALLOW:
 • the system emits a signed AuthorizationV1 artifact

This artifact contains:
 • intent_hash
 • state_hash
 • policy_id
 • issuer / audience
 • expiry
 • cryptographic signature (Ed25519)

ALLOW → AuthorizationV1 (signed, bounded, verifiable)


⸻

4. Optional Delegation

If the system involves multiple agents:
 • the original authorization can be narrowed into a DelegationV1

Properties:
 • derived from a parent AuthorizationV1
 • strictly narrower scope
 • single-hop only
 • cryptographically bound via parent hash

AuthorizationV1 → DelegationV1 (optional)


⸻

5. Mandatory Execution Boundary (PEP)

Before any action executes, a Policy Enforcement Point (PEP) must verify:
 • AuthorizationV1
or
 • DelegationV1 chain

Verification includes:
 • signature validation
 • expiry check
 • intent binding
 • state binding
 • policy consistency
 • replay protection

execution is unreachable without verification


⸻

6. Execution

Only after successful verification:

verify(...) == ok → execution allowed

Otherwise:

verify(...) != ok → fail closed (no execution)


⸻

7. Audit and Evidence

Every decision produces audit data:
 • hash-chained audit events
 • canonical state snapshot
 • policy identity

These are packaged into:

VerificationEnvelopeV1

Contains:
 • snapshot
 • audit events
 • policy binding

⸻

8. Stateless Verification

Any third party can verify:
 • AuthorizationV1
 • DelegationV1
 • VerificationEnvelopeV1

Using stateless APIs:
 • verifyAuthorization
 • verifyDelegation
 • verifyDelegationChain
 • verifyEnvelope
 • verifySnapshot
 • verifyAuditEvents

Verification result:

ok | invalid | inconclusive

Properties:
 • no access to runtime required
 • reproducible
 • portable
 • offline-capable

⸻

Key Guarantees

1. Fail-Closed Execution

If anything is invalid or ambiguous:

execution MUST NOT occur


⸻

2. Determinism

Same inputs:

(intent, state, policy)

Always produce:
 • same decision
 • same artifacts
 • same hashes

⸻

3. Pre-Execution Enforcement

Authorization is enforced:
 • before execution
 • not after
 • not probabilistically

⸻

4. Cryptographic Verifiability

All allowed actions produce:
 • signed artifacts
 • independently verifiable proofs

⸻

5. Separation of Concerns

Layer Responsibility
Agent proposes actions
PDP decides (ALLOW / DENY)
[25/03/2026 15:22] Ange 🫆: PEP verifies before execution
Execution performs side effects
Verification proves correctness


⸻

Mental Model

Agent reasoning is probabilistic

Execution must be deterministic

OxDeAI enforces that boundary.

⸻

Summary

OxDeAI implements a strict execution model:

propose → decide → authorize → verify → execute

With one critical invariant:

Execution is unreachable without verification.

