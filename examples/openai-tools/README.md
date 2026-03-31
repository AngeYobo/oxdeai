# OxDeAI Demo - Pre-Execution Authorization Boundary

Proves that OxDeAI enforces authorization constraints **before** a tool executes -
not by monitoring after the fact, but by requiring a signed Authorization artifact
before the execution boundary is crossed.

---

## What this demo shows

An agent proposes GPU provisioning three times. The policy allows exactly two.

```
Proposal 1: provision_gpu(a100, us-east-1) → ALLOW  (500 spent,  500 remaining)
Proposal 2: provision_gpu(a100, us-east-1) → ALLOW  (1000 spent,   0 remaining)
Proposal 3: provision_gpu(a100, us-east-1) → DENY   (BUDGET_EXCEEDED - tool never called)
```

The third call is blocked at the policy boundary. No tool code runs. No side effects.

The demo runs in two passes:

- **Run 1** - live authorization: engine evaluates each proposal, emits a signed artifact
- **Run 2** - offline replay: the artifact is verified independently, without the engine

---

## Architecture

```
Agent (run.ts)
  │
  │  proposed tool call: provision_gpu(asset, region)
  ▼
PEP - Policy Enforcement Point (pep.ts)
  │
  │  1. builds Intent from proposed call
  │  2. calls PDP: evaluatePure(intent, state)
  │     ├─ DENY  → tool does not execute. Return denial. Done.
  │     └─ ALLOW → Authorization artifact received
  │  3. verifies Authorization is present (invariant check)
  │  4. calls provision_gpu() only after Authorization confirmed
  │  5. returns nextState from PDP for state commitment
  │
  ▼
PDP - Policy Decision Point (policy.ts)
  │
  │  PolicyEngine.evaluatePure(intent, state)
  │
  │  Modules evaluated (in order):
  │    KillSwitch · Allowlist · Budget · PerActionCap
  │    Velocity · Replay · Concurrency · Recursion · ToolAmplification
  │
  └─ returns: { decision, authorization?, nextState?, reasons? }
```

**PDP** - evaluates policy deterministically, issues Authorizations, computes nextState.
**PEP** - enforces the authorization requirement. Thin by design. No policy logic here.

---

## Run

```bash
pnpm -C examples/openai-tools demo
```

Or from inside `examples/openai-tools`:

```bash
pnpm demo
```

No paid API calls. Tool execution is mocked. The authorization boundary is real.
The demo secret is hardcoded in the `demo` script - no env var setup needed.

---

## Shared Demo Scenario

This example is the reference implementation of the shared cross-adapter scenario in [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).

Expected visible outcome:

- proposal 1: `ALLOW`
- proposal 2: `ALLOW`
- proposal 3: `DENY`
- Run 2 replay: `ok`

---

## Expected output

```
╔══════════════════════════════════════════════════════════════════╗
║  OxDeAI - Pre-Execution Authorization Demo  (Run 1: live)        ║
║  Scenario: GPU provisioning - budget for exactly 2 proposals     ║
╚══════════════════════════════════════════════════════════════════╝

Agent:   gpu-agent-1
Policy:  budget=1000 minor units  max_per_action=500  (2× a100 allowed)

── Agent proposals ──────────────────────────────────────────────────
   provision_gpu(a100, us-east-1)  cost=500  nonce=1  → ALLOW  auth=...  instance=a100-us-east-1-demo-1
   budget after: 500/1000 minor units spent
   provision_gpu(a100, us-east-1)  cost=500  nonce=2  → ALLOW  auth=...  instance=a100-us-east-1-demo-2
   budget after: 1000/1000 minor units spent
   provision_gpu(a100, us-east-1)  cost=500  nonce=3  → DENY   BUDGET_EXCEEDED

── Summary ───────────────────────────────────────────────────────────
   proposal 1: ALLOW
   proposal 2: ALLOW
   proposal 3: DENY
   Allowed: 2   Denied: 1

── Audit chain ───────────────────────────────────────────────────────
   events:   8 hash-chained  (head hash verified in Run 2)

── Snapshot ──────────────────────────────────────────────────────────
   stateHash: ...
   size:      1275 bytes

── Envelope ──────────────────────────────────────────────────────────
   size: 4082 bytes  (ready for offline replay)

✓ Run 1 complete.  Artifact produced - pass to Run 2 for replay verification.

╔══════════════════════════════════════════════════════════════════╗
║  OxDeAI - Offline Replay Verification       (Run 2: replay)      ║
║  No engine. No agent. Artifact-only - simulates a remote PEP.    ║
╚══════════════════════════════════════════════════════════════════╝

  Input:   envelope from Run 1 (4082 bytes)
  Keyset:  issuer=oxdeai.policy-engine  kid=2026-01

── Replay result ─────────────────────────────────────────────────────
   status:        ok
   policyId:      ...
   stateHash:     ...
   auditHeadHash: ...
   violations:    none

✓ Replay passed.  Artifact verified independently - engine not involved.
```

---

## Why this is "authorization before execution"

Traditional approach: run first, check costs later (monitoring/alerting).

OxDeAI approach:
1. Agent proposes action
2. `evaluatePure(intent, state)` decides ALLOW or DENY **before any tool runs**
3. DENY → execution is structurally impossible (no code path reaches the tool)
4. ALLOW → signed Authorization is required at the PEP boundary
5. Audit chain records every decision, hash-linked and tamper-evident
6. Verification Envelope proves the history to any third party, offline - without re-running the engine

The boundary is not a rate limiter or a monitoring hook.
It is a hard pre-execution gate enforced by deterministic policy evaluation.

---

## Determinism notes

- Timestamps: fixed `DEMO_BASE_TIMESTAMP = 1_700_000_000` - no `Date.now()`, fully deterministic
- Instance IDs: stable counter (`a100-us-east-1-demo-1`, `-demo-2`) - no random entropy
- Cost table: static map in `policy.ts`, no runtime lookup
- State transitions: always via `result.nextState` from `evaluatePure`, never mutated directly
