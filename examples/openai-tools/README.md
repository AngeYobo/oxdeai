# OxDeAI Demo - Pre-Execution Economic Boundary

Proves that OxDeAI enforces economic constraints **before** a tool executes -
not by monitoring after the fact, but by requiring a signed Authorization artifact
before the execution boundary is crossed.

---

## What this demo shows

An agent proposes GPU provisioning three times. The policy allows exactly two.

```
Call 1: provision_gpu(a100, us-east-1) → ALLOW  (500 spent,  500 remaining)
Call 2: provision_gpu(a100, us-east-1) → ALLOW  (1000 spent,   0 remaining)
Call 3: provision_gpu(a100, us-east-1) → DENY   (BUDGET_EXCEEDED - tool never called)
```

The third call is blocked at the policy boundary. No tool code runs. No side effects.

At the end, a Verification Envelope is produced and verified offline - proving the
execution history is tamper-evident and auditable without re-running the engine.

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

Prerequisites: built monorepo (`pnpm build` from root).

```bash
cd examples/openai-tools
pnpm build
node dist/run.js
```

No paid API calls. Tool execution is mocked. The economic boundary is real.

## Shared Demo Scenario

This example is the reference implementation of the shared cross-adapter scenario in [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).

Expected visible outcome:

- decision 1: `ALLOW`
- decision 2: `ALLOW`
- decision 3: `DENY`
- envelope verification: `ok`

---

## Expected output

```
╔══════════════════════════════════════════════════════════════════╗
║  OxDeAI - Pre-Execution Economic Boundary Demo                   ║
║  Scenario: GPU provisioning - budget for exactly 2 calls         ║
╚══════════════════════════════════════════════════════════════════╝

Agent:   gpu-agent-1
Policy:  budget=1000 minor units  max_per_action=500  (2× a100 allowed)

── Agent proposals ──────────────────────────────────────────────────

┌─ Proposed tool call
│  provision_gpu(asset=a100, region=us-east-1)
│  cost=500 minor units  nonce=1
│  ALLOW  auth_id=...  expires=...
└─ EXECUTED  instance_id=a100-us-east-1-...
   budget after: 500/1000 minor units spent

┌─ Proposed tool call
│  provision_gpu(asset=a100, region=us-east-1)
│  cost=500 minor units  nonce=2
│  ALLOW  auth_id=...  expires=...
└─ EXECUTED  instance_id=a100-us-east-1-...
   budget after: 1000/1000 minor units spent

┌─ Proposed tool call
│  provision_gpu(asset=a100, region=us-east-1)
│  cost=500 minor units  nonce=3
└─ DENY  reasons: BUDGET_EXCEEDED

── Summary ───────────────────────────────────────────────────────────
   Allowed: 2   Denied: 1

── verifyEnvelope (strict mode) ──────────────────────────────────────
   status:        ok
   violations:    none

✓ Verification passed.
```

---

## Why this is "economic authorization before execution"

Traditional approach: run first, check costs later (monitoring/alerting).

OxDeAI approach:
1. Agent proposes action
2. `evaluatePure(intent, state)` decides ALLOW or DENY **before any tool runs**
3. DENY → execution is structurally impossible (no code path reaches the tool)
4. ALLOW → signed Authorization is required at the PEP boundary
5. Audit chain records every decision, hash-linked and tamper-evident
6. Verification Envelope proves the history to any third party, offline

The boundary is not a rate limiter or a monitoring hook.
It is a hard pre-execution gate enforced by deterministic policy evaluation.

---

## Determinism notes

- Timestamps: `Math.floor(Date.now() / 1000) + monotonic_offset` - no hidden entropy
- Cost table: static map in `policy.ts`, no runtime lookup
- State transitions: always via `result.nextState` from `evaluatePure`, never mutated directly
- Replay verification: deterministic for identical event sequences across runtimes
