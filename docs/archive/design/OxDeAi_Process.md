# OxDeAI - Execution Authorization Process

## Status

Non-normative (developer documentation)





---

# OxDeAI - Execution Authorization Process

## Overview

OxDeAI enforces **deterministic authorization at the execution boundary** of autonomous systems.

It explicitly separates two concerns:

* **Decision**: whether an action is allowed
* **Execution**: whether that action can actually occur

**Invariant:**

> No side effect is reachable unless explicitly authorized and verified.

---

## Core Model

At the center of the protocol is a deterministic evaluation:

```
(intent, state, policy) → ALLOW | DENY
```

* **intent**: proposed action (tool call, API request, infra operation, etc.)
* **state**: current system state (budgets, concurrency, replay window, etc.)
* **policy**: deterministic rules governing behavior

### Properties

* Deterministic
* Side-effect free
* Reproducible across environments

---

## High-Level Flow

```
Agent → Propose → Evaluate → Authorize → Verify → Execute
```

Each step is **strictly separated and enforced**.

---

## Step-by-Step Process

### 1. Action Proposal

An agent (LLM, workflow, automation system) proposes an action:

* Call an external API
* Provision infrastructure
* Execute a command
* Trigger a workflow

**Important:**

> This is a proposal, not execution.

---

### 2. Deterministic Policy Evaluation (PDP)

The Policy Decision Point evaluates:

```
(intent, state, policy)
```

**Output:**

* `ALLOW`
* `DENY`

**Properties:**

* No randomness
* No hidden state
* No external dependencies
* Fail-closed by default

---

### 3. Decision Outcomes

#### DENY

* Execution is blocked
* No side effects occur
* Audit event is recorded

```
DENY → no execution
```

---

#### ALLOW

* System emits a signed **AuthorizationV1** artifact

**Contains:**

* `intent_hash`
* `state_hash`
* `policy_id`
* `issuer / audience`
* `expiry`
* `signature (Ed25519)`

```
ALLOW → AuthorizationV1 (signed, bounded, verifiable)
```

---

### 4. Optional Delegation

In multi-agent systems:

* Authorization can be narrowed into **DelegationV1**

**Properties:**

* Derived from parent AuthorizationV1
* Strictly narrower scope
* Single-hop only
* Cryptographically bound (parent hash)

```
AuthorizationV1 → DelegationV1 (optional)
```

---

### 5. Mandatory Execution Boundary (PEP)

Before execution, the **Policy Enforcement Point (PEP)** verifies:

* AuthorizationV1
  **or**
* DelegationV1 chain

**Verification includes:**

* Signature validation
* Expiry check
* Intent binding
* State binding
* Policy consistency
* Replay protection

**Invariant:**

> Execution is unreachable without verification.

---

### 6. Execution

```
verify(...) == ok → execution allowed
verify(...) != ok → fail closed (no execution)
```

---

### 7. Audit and Evidence

Each decision produces audit data:

* Hash-chained audit events
* Canonical state snapshot
* Policy identity

Packaged into:

### VerificationEnvelopeV1

**Contains:**

* Snapshot
* Audit events
* Policy binding

---

### 8. Stateless Verification

Any third party can verify:

* AuthorizationV1
* DelegationV1
* VerificationEnvelopeV1

**APIs:**

* `verifyAuthorization`
* `verifyDelegation`
* `verifyDelegationChain`
* `verifyEnvelope`
* `verifySnapshot`
* `verifyAuditEvents`

**Result:**

```
ok | invalid | inconclusive
```

**Properties:**

* No runtime access required
* Reproducible
* Portable
* Offline-capable

---

## Key Guarantees

### 1. Fail-Closed Execution

If anything is invalid or ambiguous:

> Execution MUST NOT occur

---

### 2. Determinism

Same inputs:

```
(intent, state, policy)
```

Always produce:

* Same decision
* Same artifacts
* Same hashes

---

### 3. Pre-Execution Enforcement

Authorization is enforced:

* Before execution
* Not after
* Not probabilistically

---

### 4. Cryptographic Verifiability

All allowed actions produce:

* Signed artifacts
* Independently verifiable proofs

---

### 5. Separation of Concerns

| Layer        | Responsibility            |
| ------------ | ------------------------- |
| Agent        | Proposes actions          |
| PDP          | Decides (ALLOW / DENY)    |
| PEP          | Verifies before execution |
| Execution    | Performs side effects     |
| Verification | Proves correctness        |

---

## Mental Model

* Agent reasoning is **probabilistic**
* Execution must be **deterministic**

> OxDeAI enforces that boundary.

---

## Summary

OxDeAI implements a strict execution pipeline:

```
propose → decide → authorize → verify → execute
```

**Critical invariant:**

> Execution is unreachable without verification.
