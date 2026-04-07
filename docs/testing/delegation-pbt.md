# Delegation PBT - Design Notes

## Status

Non-normative (developer documentation)






> Non-normative document.  
> This file describes property-based testing strategies and coverage for DelegationV1.  
> It is intended for developer workflows and test validation only.  
>  
> See SPEC.md and docs/spec/* for authoritative protocol definitions and requirements.

Property-based test coverage for `DelegationV1` across `@oxdeai/core`,
`@oxdeai/guard`, and `@oxdeai/compat`.

---

## Test IDs

| ID   | Package          | File                                      | Invariant                                       |
|------|------------------|-------------------------------------------|-------------------------------------------------|
| D-P1 | core             | `delegation.property.test.ts`             | Canonical hash is key-order-insensitive         |
| D-P2 | core             | `delegation.property.test.ts`             | Valid delegation chain always verifies OK       |
| D-P3 | core             | `delegation.property.test.ts`             | Expired delegation always fails closed          |
| D-P4 | core             | `delegation.property.test.ts`             | Delegatee mismatch always fails closed          |
| D-P5 | core             | `delegation.property.test.ts`             | Any field mutation invalidates the delegation   |
| G-D1 | guard            | `guard.delegation.property.test.ts`       | In-scope action is allowed; setState not called |
| G-D2 | guard            | `guard.delegation.property.test.ts`       | All invalid delegation classes fail closed      |
| G-D3 | guard            | `guard.delegation.property.test.ts`       | Wrong parent authorization fails closed         |
| CA-1 | compat           | `cross-adapter.test.ts`                   | Same intent + state → same decision, all adapters |
| CA-6 | compat           | `cross-adapter.test.ts`                   | Per-action cap boundary (inclusive-allow)       |
| CA-7 | compat           | `cross-adapter.test.ts`                   | Per-action cap exceeded → `PER_ACTION_CAP_EXCEEDED` |
| CA-8 | compat           | `cross-adapter.test.ts`                   | PBT: seeded variation, decision + evidence equivalence |
| CA-9 | compat           | `cross-adapter.test.ts`                   | Nonce replay → `REPLAY_NONCE` across all adapters |
| CA-10| compat           | `cross-adapter.test.ts`                   | Concurrent isolation (I6 regression test)       |

---

## Mapping to Protocol Invariants

| Test ID | Invariant | What It Enforces |
|---------|-----------|-----------------|
| D-P1 | I1 - Canonical hash key-order independence | `delegationParentHash` and `canonicalJson` of the signing payload are invariant to object key insertion order at all nesting depths |
| D-P2 | DelegationV1 valid chain | Any delegation with a narrowing scope and a valid parent verifies OK across all seed variations |
| D-P3 | DelegationV1 expiry ceiling | Any delegation where `expiry > parent.expiry` is always rejected (`DELEGATION_EXPIRY_EXCEEDS_PARENT`) |
| D-P4a / D-P4b | DelegationV1 scope narrowing | Any `max_amount` or `tools` widening relative to parent scope is always rejected (`DELEGATION_SCOPE_VIOLATION`) |
| D-P5 | DelegationV1 signature coverage | Mutation of any signed field (all 15 named mutations including `scope.tools:duplicate`) is always detected; result is `ok: false` with a violation in the TAMPER_CODES set |
| G-D1 | Delegation guard allow path | An in-scope action always reaches `execute`; `setState` is never called on the delegation path |
| G-D2 | Fail-Closed | All three invalid delegation classes (expired, tampered, out-of-scope) always throw `OxDeAIDelegationError`; `execute` and `setState` are never called |
| G-D3 | Delegation parent hash binding | A delegation presented with any wrong parent (`auth_id` differs) is always rejected with `DELEGATION_PARENT_HASH_MISMATCH` |
| CA-1 | I6 - Evaluation Isolation; cross-adapter decision equivalence | Same conceptual action + isolated state snapshot → same `ALLOW`/`DENY` decision, `action_type`, `amount`, `metadata_hash`, `timestamp`, `agent_id`, and denial reasons across LangGraph, OpenAI Agents, and CrewAI |
| CA-6 | Per-action cap boundary | `estimatedCost` exactly equals cap → ALLOW (inclusive boundary) |
| CA-7 | Per-action cap exceeded | `estimatedCost` exceeds cap by 1 → DENY + `PER_ACTION_CAP_EXCEEDED` |
| CA-8 | PBT sweep | Seeded variation - same decision + normalization evidence across all adapters |
| CA-9 | Nonce replay | Pre-recorded nonce + fixed-nonce normalizer → DENY + `REPLAY_NONCE` across all adapters |
| CA-10 | I6 - Concurrent isolation | 30 parallel calls with shared tight budget → all ALLOW only with isolated state |

---

## Cross-Adapter Boundary and Isolation Tests

These tests validate that equivalent intents produce equivalent authorization outcomes
across all supported adapters (LangGraph, OpenAI Agents SDK, CrewAI),
including boundary conditions, replay protection, and concurrency behavior.

| Test ID | Name | What it proves | Invariant |
|---------|------|----------------|-----------|
| CA-6 | `amount-at-cap` | `estimatedCost` exactly equals `max_amount_per_action` → ALLOW across all adapters; no off-by-one in cap enforcement | Per-action cap boundary; cross-adapter consistency |
| CA-7 | `amount-exceeds-cap` | `estimatedCost` exceeds cap by 1 → DENY with `PER_ACTION_CAP_EXCEEDED` across all adapters; violation class is stable and consistent | Per-action cap enforcement; cross-adapter consistency |
| CA-8 | PBT sweep | Seeded variation over tool names and costs covers both ALLOW and DENY branches; all adapters agree on decision, `action_type`, `amount`, `metadata_hash`, `timestamp`, `agent_id`, and denial reasons | I1–I4, cross-adapter decision equivalence |
| CA-9 | Nonce replay | Pre-recorded nonce reused via fixed-nonce normalizer → DENY with `REPLAY_NONCE` across all adapters; proves replay protection is not broken by any adapter's field mapping | Replay protection; cross-adapter consistency |
| CA-10 | Concurrent isolation | 30 parallel evaluations (10 per adapter) with combined cost exceeding a tight budget → all ALLOW only when each call receives an isolated state snapshot; detects shared-state mutation | I6 - Evaluation Isolation |

The concurrent isolation test (CA-10) is a regression test for I6. It ensures
that cross-adapter determinism is preserved under parallel execution: if
`getState` returns the same mutable reference, `deepMerge` inside
`evaluatePure` corrupts the shared budget, and later calls DENY spuriously.

---

## Boundary Semantics

`BudgetModule` enforces:

```
DENY if intent.amount > cap
```

Equality (`intent.amount == cap`) is allowed. The boundary is inclusive-allow.

This condition is explicitly tested:

- CA-6: `estimatedCost=500`, `cap=500_000_000n` (500 units) → `amount == cap` → ALLOW
- CA-7: `estimatedCost=501` → `amount = cap + 1_000_000n` → DENY (`PER_ACTION_CAP_EXCEEDED`)

---

## Determinism and State Isolation

OxDeAI evaluation assumes a pure, deterministic model:

```
(intent, state, policy_version) → decision
```

This model holds **only when state is treated as an immutable input**.
`PolicyEngine.evaluatePure` accumulates module state deltas into a new
`working` object - but the accumulation uses shallow merging, so nested
objects inside the original `state` can be mutated in place.

### Failure mode

When a mutable state object is shared across concurrent evaluations:

1. Adapter A calls `evaluatePure(intentA, state)`.
2. `deepMerge(state, delta)` mutates `state.budget.spent_in_period` and
   `state.replay.nonces` as a side effect.
3. Adapter B calls `evaluatePure(intentB, state)` - now reads the mutated
   budget/nonce values from step 2.
4. Adapter B sees a partially-spent budget or a stale nonce list and may
   produce `BUDGET_EXCEEDED` or `REPLAY_NONCE` even though its intent is
   independently valid.

This was observed in `cross-adapter.test.ts`: with `Promise.all`, LangGraph's
evaluation ran first and mutated the shared state object before OpenAI Agents
and CrewAI resumed, causing divergent `ALLOW`/`DENY` outcomes for the same
conceptual action.

### Resolution pattern

Each evaluation must receive an isolated snapshot:

```typescript
getState: () => structuredClone(POLICY_STATE)
```

This guarantees:

- **Concurrency safety** - no evaluation can observe another's in-progress
  state delta.
- **Reproducibility** - the same `POLICY_STATE` constant produces the same
  decision on every invocation regardless of call order.
- **Invariant preservation** - I6 (Evaluation Isolation) holds unconditionally.

---

## Policy Version Consistency

`state.policy_version` MUST match `engine.policy_version` (the
`policy_version` option passed to the `PolicyEngine` constructor).

A mismatch causes `evaluatePure` to return immediately with:

```
{ decision: "DENY", reasons: ["POLICY_VERSION_MISMATCH"] }
```

This check fires before any policy module runs, so the denial reason is
`POLICY_VERSION_MISMATCH`, not `ALLOWLIST_ACTION` or any other module code.

**Why it matters:**

- Ensures that authorization artifacts are only issued under the policy
  version that was in effect when the intent was evaluated.
- Prevents replay of old authorizations against a newer (or different)
  policy configuration.
- Provides a deterministic, unambiguous signal when state and engine are
  misconfigured.

**Common mistake in tests:**

`buildState` defaults `policy_version` to `"v1"`. If the engine is
constructed with a non-default `policy_version`, the state must be built
with the matching value:

```typescript
const ENGINE = new PolicyEngine({ policy_version: "v1-my-test", ... });

const STATE = buildState({
  agent_id: "...",
  policy_version: "v1-my-test",   // must match ENGINE
  ...
});
```

---

## Invariant I6 - Evaluation Isolation

See [invariants.md](../invariants.md#i6--evaluation-isolation).
