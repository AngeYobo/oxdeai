# Invariants

## Status

Non-normative (developer documentation)






Protocol-level invariants defined from v1.0.0. Extended with delegation invariants in v1.3.0.

## I1 - Canonical hashing ignores key insertion order
Equivalent objects with different insertion order produce identical canonical hashes.

## I2 - Snapshot round-trip determinism
`export -> encode -> decode -> import` preserves canonical state hash.

## I3 - Decision equivalence across import/export
For identical intent sequence and equivalent state, decisions and resulting hashes are identical.

## I4 - Replay verification determinism
Given identical audit events, recomputed verification output is identical.

## I5 - Cross-process consistency
Independent runs with same inputs produce identical deterministic identifiers.

## I6 - Evaluation Isolation
Concurrent evaluations MUST NOT share a mutable state object. Each call to
`evaluatePure` must receive an isolated snapshot of state. Sharing a mutable
reference breaks determinism: in-flight `deepMerge` side effects can cause
one evaluation to observe another's partial budget or replay mutations,
producing non-deterministic `ALLOW`/`DENY` outcomes for identical inputs.
Resolution: `getState: () => structuredClone(state)`.

## Intent Binding Invariant
`intent_hash` includes only v1.0 binding fields and excludes `signature` and unknown fields.

## Fail-Closed Invariant
Malformed/invalid protocol artifacts must produce denial (`invalid` or deny/no-execute behavior).

---

## Conformance Mapping

| Invariant | Name | Description | Covered By | Coverage Type |
|---|---|---|---|---|
| I1 | Canonical hash key-order independence | Equivalent objects with different key insertion order produce identical canonical hashes | `core/property.test.ts` (I1), `core/delegation.property.test.ts` (D-P1) | unit, PBT |
| I2 | Snapshot round-trip determinism | `export → encode → decode → import` preserves canonical state hash | `core/property.test.ts` (I2), `core/verify.snapshot.test.ts` | unit |
| I3 | Decision equivalence across import/export | Identical intent sequence + equivalent state → identical decisions and hashes | `core/property.test.ts` (I3) | unit |
| I4 | Replay verification determinism | Identical audit events → identical recomputed verification output | `core/property.test.ts` (I4), `core/replay.verify.test.ts` | unit |
| I5 | Cross-process consistency | Independent processes with same inputs produce identical deterministic identifiers | `core/cross_process.test.ts` | integration |
| I6 | Evaluation isolation | Concurrent evaluations MUST NOT share mutable state | `compat/cross-adapter.test.ts` (CA-1, CA-10) | PBT, cross-adapter, concurrency |
| Intent Binding | Intent hash field binding | `intent_hash` excludes `signature` and unknown fields | `core/intent.hash.test.ts` | unit |
| Fail-Closed | Fail-closed on invalid artifacts | Malformed or invalid artifacts produce denial; execute is never called | `core/delegation.test.ts`, `core/delegation.matrix.test.ts`, `guard/guard.test.ts`, `guard/guard.property.test.ts` (G1, G2), `guard/guard.delegation.property.test.ts` (G-D2, G-D3) | unit, matrix, PBT |
| - | DelegationV1 valid chain | Any valid narrowing scope produces a verifiable delegation chain | `core/delegation.property.test.ts` (D-P2) | PBT |
| - | DelegationV1 expiry ceiling | Delegation expiry exceeding parent is always rejected | `core/delegation.property.test.ts` (D-P3), `core/delegation.matrix.test.ts` (CASE-3d) | PBT, matrix |
| - | DelegationV1 scope narrowing | Scope widening in any dimension is always rejected | `core/delegation.property.test.ts` (D-P4a, D-P4b), `core/delegation.matrix.test.ts` (CASE-2a–2f) | PBT, matrix |
| - | DelegationV1 signature coverage | Mutation of any signed field is always detected | `core/delegation.property.test.ts` (D-P5) | PBT |
| - | Delegation guard allow path | In-scope action is allowed; setState is never called on delegation path | `guard/guard.delegation.property.test.ts` (G-D1) | PBT |
| - | Delegation parent hash binding | Delegation presented with wrong parent is rejected with `DELEGATION_PARENT_HASH_MISMATCH` | `guard/guard.delegation.property.test.ts` (G-D3), `core/delegation.matrix.test.ts` (CASE-5a) | PBT, matrix |
| - | Cross-adapter decision equivalence | Same intent + state → same decision across LangGraph, OpenAI Agents, CrewAI | `compat/cross-adapter.test.ts` (CA-1, CA-8) | corpus, PBT |
| - | Per-action cap boundary | `intent.amount == cap` → ALLOW (inclusive); `intent.amount > cap` → DENY (`PER_ACTION_CAP_EXCEEDED`) | `compat/cross-adapter.test.ts` (CA-6, CA-7) | corpus |
| - | Replay protection portability | Pre-recorded nonce reused via fixed normalizer → DENY (`REPLAY_NONCE`) across all adapters | `compat/cross-adapter.test.ts` (CA-9) | corpus |
| - | Policy version consistency | `state.policy_version` mismatch → `POLICY_VERSION_MISMATCH` before any module runs | `compat/cross-adapter.test.ts` (implicit - misconfigured version causes uniform DENY) | integration |
