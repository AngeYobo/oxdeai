# OxDeAI Protocol Specification

Version: 1.0.0  
Status: Stable

## 1. Introduction
OxDeAI is a deterministic economic containment protocol for autonomous systems and AI agents. It enforces economic constraints before execution, so systems can decide whether an action is economically permissible prior to calling external tools, APIs, payment rails, or infrastructure.

OxDeAI addresses operational failure modes including:
- runaway agent spending
- uncontrolled tool/API execution
- recursive planning explosions
- unbounded concurrency growth
- replayed actions and duplicate effects

This document defines the protocol, not a specific implementation. Any language/runtime implementation is compliant if it satisfies this specification and produces equivalent deterministic outcomes.

## 2. Protocol Design Principles
OxDeAI implementations MUST follow these principles:
- Deterministic evaluation: identical `(intent, state, policy configuration)` MUST produce identical outputs.
- Fail-closed behavior: malformed state/intent or verification ambiguity MUST deny execution.
- Portable state: policy state MUST be serializable into canonical snapshots for transfer and verification.
- Verifiable artifacts: outputs MUST be independently verifiable without engine re-execution when possible.
- Replayable history: audit traces MUST support deterministic integrity validation.

## 3. Core Concepts
### Intent
A structured request describing a proposed economic action.
Purpose: input to policy evaluation.

### State
The full policy state at evaluation time.
Purpose: source of economic limits and counters.

### Policy Engine
A deterministic function over `(intent, state)` producing decision artifacts.
Purpose: decide ALLOW or DENY and compute next state.

### Authorization
A signed artifact emitted only on ALLOW.
Purpose: bind a permitted action to policy identity, state hash, and expiry.

### Audit Event
An append-only event describing evaluation lifecycle transitions.
Purpose: create tamper-evident execution history.

### Canonical Snapshot
Canonical serialized state artifact.
Purpose: cross-runtime portability and deterministic hashing.

### Verification Envelope
Portable bundle containing snapshot bytes and audit events.
Purpose: third-party stateless verification.

## 4. Intent Structure
An intent MUST be a deterministic object with protocol-defined fields.

Example shape:
```json
{
  "agent_id": "agent-1",
  "action_type": "PAYMENT",
  "amount": "1000000",
  "nonce": "42",
  "timestamp": 1730000000,
  "depth": 0,
  "tool": "openai.responses"
}
```

Field semantics:
- `agent_id`: principal requesting action.
- `action_type`: protocol action category.
- `amount`: fixed-point integer quantity in the smallest denomination of the applicable asset/unit. Implementations MUST treat `amount` as an integer count of minor units and MUST NOT interpret it as floating point. If `asset` is present in the intent, denomination is resolved from that field; if `asset` is absent, denomination MUST be resolved from policy context for the action.
- `nonce`: per-agent uniqueness input for replay protection.
- `timestamp`: UNIX seconds used by time-window rules.
- `depth`: recursion/planning depth for bounded recursion control.
- `tool`: optional tool/API identifier for amplification controls.

Implementations MAY include additional fields. For deterministic identity, implementations MUST define a canonical binding set for intent hashing and MUST apply it consistently across signing and verification. Unknown/non-binding fields MUST be excluded from canonical intent identity; binding fields MUST be included.

For v1.0, the canonical `intent_hash` binding set is:
- `intent_id`
- `agent_id`
- `action_type`
- `depth`
- `amount`
- `asset`
- `target`
- `timestamp`
- `metadata_hash`
- `nonce`
- `type`
- `authorization_id`
- `tool`
- `tool_call`

`signature` MUST be excluded from `intent_hash`. Unknown fields not listed above MUST be excluded.

## 5. Policy State
State MUST contain module-relevant slices. Typical slices include:
- budget state (`budget_limit`, `spent_in_period`)
- velocity counters (window config + counters)
- replay window (`window_seconds`, nonce history)
- recursion limits (`max_depth`)
- concurrency (`max_concurrent`, active slots)
- kill switches (global/per-agent)
- allowlists (action, asset, target)
- tool amplification limits (`max_calls`, call history)

State evolution rule:
- Each evaluation computes a deterministic `nextState`.
- DENY MUST NOT commit partial mutations.
- ALLOW state transitions MUST be deterministic and fully derivable from prior state plus intent.
- State/module keys MUST be serialized with deterministic sorted-key ordering for canonical hashing and cross-runtime consistency.

## 6. Deterministic Evaluation
Protocol function:
```text
evaluate(intent, state) -> { decision, reasons?, authorization?, nextState? }
```

Decision semantics:
- `ALLOW`: action is economically permitted.
- `DENY`: action is blocked; execution MUST NOT proceed.

Determinism requirements:
- Module ordering MUST be stable.
- State merge/transition order MUST be stable.
- Evaluation MUST avoid hidden entropy (e.g., random values, implicit wall-clock access in strict deterministic mode).
- Equivalent semantic inputs MUST produce identical decision artifacts.

Clock source rule:
- Time-dependent evaluation MUST use an explicit timestamp input.
- Implementations MUST NOT call system wall-clock APIs inside deterministic evaluation logic.
- If an implementation supports non-strict mode with implicit clock fallback, strict deterministic mode MUST disable that fallback.

## 7. Authorization
Authorization is emitted only on ALLOW.

Canonical fields:
- `intent_hash`
- `policy_id`
- `state_hash`
- `expires_at`
- `signature`

Example:
```json
{
  "intent_hash": "<hex>",
  "policy_id": "<hex>",
  "state_hash": "<hex>",
  "expires_at": 1730000060,
  "signature": "<hex>"
}
```

Signature algorithm:
- Reference profile: HMAC-SHA256 over canonical serialized authorization payload.
- Compliant implementations MUST use canonical serialization for signing and verification.
- The canonical signing payload for v1.0 MUST include exactly these fields: `intent_hash`, `policy_id`, `state_hash`, `expires_at`.
- Payload keys MUST be serialized in canonical sorted-key order prior to signature computation.
- Signature is proof; intent identity SHOULD be derived from canonical unsigned intent payload.
- `expires_at` MUST be computed deterministically. The v1.0 reference rule is: `expires_at = intent.timestamp + authorization_ttl_seconds`, where `authorization_ttl_seconds` is policy configuration.

Canonical signing payload example:
```json
{
  "expires_at": 1730000060,
  "intent_hash": "<hex>",
  "policy_id": "<hex>",
  "state_hash": "<hex>"
}
```

## 8. Canonical Snapshots
Snapshot format is versioned.

CanonicalState v1:
```json
{
  "formatVersion": 1,
  "engineVersion": "1.0.0",
  "policyId": "<hex>",
  "modules": {
    "BudgetModule": {"budget_limit": {"agent-1": "10000"}}
  }
}
```

Rules:
- Encoding MUST be canonical JSON.
- Object keys MUST be sorted deterministically.
- Integer-like large values (e.g., BigInt) MUST be normalized to canonical decimal strings.
- `formatVersion` MUST be validated on decode.
- `policyId` binding MUST be enforced at import/verification boundaries.
- `engineVersion` MUST be parsed and surfaced by verifiers; mismatch against local runtime version SHOULD be treated as a compatibility warning, not an automatic protocol-invalid condition.

## 9. Audit Chain
Evaluation emits ordered audit events.

Event examples:
- `INTENT_RECEIVED`
- `DECISION`
- `AUTH_EMITTED`
- optional `STATE_CHECKPOINT`

Hash chaining rule:
```text
genesis = SHA256("OxDeAI::GENESIS::v1")
head_0 = genesis
head_1 = SHA256(head_0 || 0x0A || canonical(event_0))
head_(k+1) = SHA256(head_k || 0x0A || canonical(event_k))
```

Tamper detection:
- Any event mutation, insertion, deletion, or reorder changes downstream head hash.
- Recomputed head mismatch implies trace integrity failure.

## 10. Replay Verification
Replay verification validates an event sequence without executing business side effects.

Checks:
- policy consistency (`policyId` invariants)
- non-decreasing timestamps
- chain hash recomputation integrity
- state checkpoint anchor presence in strict mode

Result statuses:
- `ok`: checks passed
- `invalid`: integrity/policy/timestamp violations
- `inconclusive`: no invalid violation, but strict anchoring requirement not satisfied

Host runtime handling:
- Hosts MUST treat `invalid` as deny/no-execute.
- Hosts SHOULD treat `inconclusive` as deny/no-execute in fail-closed deployments.
- If a host permits `inconclusive`, it MUST apply an explicit local override policy outside this protocol.

## 11. Verification Envelope
Envelope format (`VerificationEnvelopeV1`) combines snapshot bytes and audit events.

Wire shape:
```json
{
  "formatVersion": 1,
  "snapshot": "<base64>",
  "events": []
}
```

Verification procedure:
1. Decode envelope and validate schema.
2. Verify snapshot integrity (decode success, schema/version validation, canonical state-hash recomputation from snapshot payload, and policyId checks).
3. Verify audit sequence integrity.
4. Enforce policy identity consistency across snapshot and audit.
5. Return canonical `VerificationResult` with `ok | invalid | inconclusive`.

## 12. Module Interface
Policy behavior is composed from deterministic modules.

Each module MUST define:
- state schema it reads/writes
- deterministic evaluation rule
- deterministic state transition rule

Module contract:
```text
module.evaluate(intent, state) -> { decision, reasons?, stateDelta? }
```

`stateDelta` semantics:
- `stateDelta` MUST be a deterministic partial-state patch.
- Patches MUST be merged using deterministic deep-merge semantics with stable key ordering.
- Implementations MUST NOT commit partial deltas when final decision is `DENY`.
- For `ALLOW`, final `nextState` MUST be exactly reproducible from `(state, ordered module deltas)`.

Module requirements:
- no hidden entropy
- deterministic serialization for hashed state
- explicit validation and fail-closed behavior

## 13. Deterministic Invariants
Implementations MUST maintain invariants including:
- Canonical hashing ignores key insertion order.
- Snapshot export/import round-trip is deterministic.
- Replay verification is deterministic for identical event sequences.
- Cross-runtime results are consistent for identical canonical inputs.
- Stable identifiers (`policyId`, `stateHash`, `auditHeadHash`) reproduce across processes.

## 14. Security Considerations
OxDeAI is designed to reduce economic risk from autonomous execution.

Threat classes addressed:
- replay attacks via nonce windows and replay checks
- runaway loops via velocity/tool-call amplification controls
- unbounded concurrency via slot limits and release rules
- silent budget drain via per-period budgets and per-action caps

Operational guidance:
- use strict deterministic mode in safety-critical flows
- verify signatures before execution
- verify envelope artifacts offline for disputes/settlement
- deny on malformed or ambiguous inputs

## 15. Implementation Notes
`@oxdeai/core` is the TypeScript reference implementation of this protocol (`npm:@oxdeai/core@1.0.0`; repository path: `packages/core`).

Conformance model:
- The protocol is implementation-independent.
- Other languages/runtimes MAY implement OxDeAI if they preserve canonical formats, deterministic evaluation semantics, verification outputs, and invariant behavior defined in this specification.
- Implementations SHOULD validate against shared protocol test vectors (known inputs and expected hashes/decisions) to demonstrate cross-runtime conformance.
