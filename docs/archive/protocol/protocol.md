# OxDeAI Protocol (Legacy v1.0.2 Profile)

## Status

Non-normative (developer documentation)





This document is a companion reference (non-normative). Normative definitions are in [../SPEC.md](../SPEC.md) and `docs/spec/`; artifact status (Draft/Stable) is defined there.

> ⚠️ **Archival profile only.**
> This document has been superseded. The canonical archival location is:
> [`docs/archive/PROTOCOL-v1.0.2.md`](../docs/archive/PROTOCOL-v1.0.2.md)
>
> For the current protocol, see:
> - [`PROTOCOL.md`](../PROTOCOL.md) - current front-door overview
> - [`SPEC.md`](../SPEC.md) - current normative specification

# OxDeAI Protocol (Legacy v1.0.2 Profile)

This document preserves the v1.0.2 protocol profile for archival/reference compatibility.
The canonical archival copy is at [`docs/archive/PROTOCOL-v1.0.2.md`](../docs/archive/PROTOCOL-v1.0.2.md).
Reference locked vectors (current line): `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.

## 1. Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 2. Scope and Goals

OxDeAI defines deterministic economic containment for autonomous systems.

Given `(intent, state)`, a compliant implementation produces deterministic outputs:

- `decision` (`ALLOW` or `DENY`)
- `authorization` (only when `ALLOW`)
- `nextState` (only when `ALLOW`)
- audit events for verifiable replay

This protocol is implementation-independent. `@oxdeai/core` is a reference implementation, not the protocol itself.

---

## 3. Glossary

- **Intent**: requested action, actor, amount, nonce, timestamp, and related context.
- **State**: policy state used for evaluation and mutation.
- **PolicyEngine**: deterministic evaluator over `(intent, state)`.
- **CanonicalState**: portable canonical snapshot object.
- **Authorization**: signed, expiring allow artifact bound to intent and state hash.
- **AuditEvent**: append-only event emitted during evaluation.
- **Audit Head Hash**: chain tip hash over ordered audit events.
- **VerificationEnvelopeV1**: portable artifact containing snapshot + events.
- **VerificationResult**: unified verifier output (`ok|invalid|inconclusive`) with violations. Protocol decisions remain ALLOW/DENY with deterministic error codes defined in the specs; `ok/invalid/inconclusive` are interface-level summaries only.

---

## 4. Threat Model

OxDeAI addresses these classes of failures:

- runaway spending
- replayed intents / duplicate effects
- unbounded concurrency
- recursion/amplification loops
- tampered or reordered audit traces
- schema corruption / malformed inputs

OxDeAI does **not** replace domain authn/authz, settlement finality, or infrastructure-level fault tolerance.

---

## 5. Canonical JSON Rules (Normative)

All protocol hashing/encoding paths MUST use canonical JSON per `canonicalization-v1`; all hashes and signature preimages MUST use `canonicalization-v1`.

Canonicalization rules:

1. Objects: keys MUST be sorted lexicographically ascending.
2. Arrays: order MUST be preserved as provided by protocol rules.
3. `undefined`: MUST normalize to `null` before serialization.
4. BigInt / integer values outside JSON safe range: MUST be encoded as base-10 strings.
5. Non-finite numbers (`NaN`, `+/-Infinity`) MUST be rejected.
6. UTF-8 encoding MUST be used for bytes prior to hashing.

`sha256HexFromJson(x)` is defined as:

- `sha256( utf8(canonicalJson(x)) )` in lowercase hex.

---

## 6. Intent Schema and Hashing

## 6.1 Intent fields

A protocol Intent MUST include:

- `intent_id: string`
- `agent_id: string`
- `action_type: "PAYMENT" | "PURCHASE" | "PROVISION" | "ONCHAIN_TX"`
- `amount: bigint` (semantic integer quantity; unit determined by `asset` or policy context)
- `target: string`
- `timestamp: number` (unix seconds, integer)
- `metadata_hash: string`
- `nonce: bigint`
- `signature: string`

Optional:

- `depth?: number`
- `asset?: string`
- `type?: "EXECUTE" | "RELEASE"` (default `EXECUTE`)
- `authorization_id?` (REQUIRED when `type="RELEASE"`)
- `tool?: string`
- `tool_call?: boolean`

## 6.2 Binding projection for `intent_hash`

`intent_hash` MUST be computed from canonical JSON over the following binding fields only (if present):

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

`signature` MUST NOT be included in `intent_hash`.  
Unknown/non-binding fields MUST NOT affect `intent_hash`.

### Example Intent JSON

```json
{
  "intent_id": "intent-42",
  "agent_id": "agent-1",
  "action_type": "PROVISION",
  "type": "EXECUTE",
  "amount": "320",
  "asset": "GPU_MINUTE",
  "target": "us-east-1",
  "timestamp": 1772718102,
  "metadata_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "nonce": "1",
  "signature": "agent-signature-placeholder",
  "tool_call": true,
  "tool": "openai.responses"
}
```

---

## 7. Policy State and Canonical Snapshots

## 7.1 Normative State fields

A conforming state MUST include:

- `policy_version: string`
- `period_id: string`
- `kill_switch`
- `allowlists`
- `budget`
- `max_amount_per_action`
- `velocity`
- `replay`
- `concurrency`
- `recursion`
- `tool_limits`

Per-agent required config MUST exist for the evaluated `intent.agent_id`:
budget/caps/concurrency/recursion/tool limits.

## 7.2 CanonicalState (snapshot object)

`CanonicalState` MUST be:

```json
{
  "formatVersion": 1,
  "engineVersion": "string",
  "policyId": "string",
  "modules": {}
}
```

Rules:

- `formatVersion` MUST equal `1`.
- `modules` MUST be a JSON object (`Record<string, unknown>`).
- Snapshot bytes MUST be `utf8(canonicalJson(CanonicalState))`.

### Example CanonicalState JSON

```json
{
  "formatVersion": 1,
  "engineVersion": "1.0.2",
  "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de",
  "modules": {
    "BudgetModule": {
      "budget_limit": { "agent-1": "1000000" },
      "spent_in_period": { "agent-1": "320" }
    },
    "VelocityModule": {
      "config": { "window_seconds": 60, "max_actions": 10 },
      "counters": { "agent-1": { "window_start": 1772718102, "count": 1 } }
    }
  }
}
```

---

## 8. Authorization Artifact

On `ALLOW`, an Authorization MUST be emitted with:

- `authorization_id: string`
- `intent_hash: string`
- `policy_version: string` (policy binding identifier in v1 reference profile)
- `state_snapshot_hash: string`
- `decision: "ALLOW"`
- `expires_at: number` (unix seconds)
- `engine_signature: string` (HMAC-SHA256 hex)

Signing payload MUST be canonical JSON over:

- `intent_hash`
- `policy_version`
- `state_snapshot_hash`
- `decision`
- `expires_at`

`expires_at` MUST be computed as:

- `intent.timestamp + authorization_ttl_seconds`

`authorization_id` SHOULD be deterministic from payload + signature (reference profile: SHA-256 of canonical payload with signature included).

### Example Authorization JSON

```json
{
  "authorization_id": "19e9022f6bc34e77489c3c480629ae41a68f17c8b42685c482ae060755b800ef",
  "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
  "policy_version": "v1",
  "state_snapshot_hash": "8e0d8542b8c9b02fdd9862d720f4755ff3ae04bd51fae5fb58dae7089ddf1beb",
  "decision": "ALLOW",
  "expires_at": 1772718222,
  "engine_signature": "hex-hmac-sha256"
}
```

---

## 9. Audit Events and Hash Chaining

## 9.1 Event union

Audit events MUST be one of:

- `INTENT_RECEIVED`
- `DECISION`
- `AUTH_EMITTED`
- `EXECUTION_ATTESTED`
- `STATE_CHECKPOINT`

All events MUST include:

- `timestamp: number` (finite, unix seconds)
- optional `policyId: string`

`STATE_CHECKPOINT` MUST include:

- `stateHash: string` (64 lowercase hex) when used as strict anchor.

## 9.2 Chain algorithm

Canonical event bytes are computed from event object with:

- `policyId` normalized as `policyId ?? null`
- canonical JSON, UTF-8 bytes

Chain recurrence:

- `head_0 = ""` (empty UTF-8 string)
- `head_{n+1} = sha256_hex( head_n || "\n" || canonical_event_bytes_n )`

Events MUST be processed in order.  
`timestamp` MUST be non-decreasing across the sequence.

### Example audit excerpt

```json
[
  {
    "type": "INTENT_RECEIVED",
    "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
    "agent_id": "agent-1",
    "timestamp": 1772718102,
    "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de"
  },
  {
    "type": "DECISION",
    "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
    "decision": "ALLOW",
    "reasons": [],
    "policy_version": "v1",
    "timestamp": 1772718102,
    "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de"
  }
]
```

Example resulting head hash:
`3cb6631cf0202df06094502b085878b2ad93bb0dbab590144ac6be1cd37d044e`

---

## 10. Stateless Verification APIs

The protocol defines three pure verifiers:

- `verifySnapshot(snapshotBytes)`
- `verifyAuditEvents(events, opts?)`
- `verifyEnvelope(envelopeBytes, opts?)`

All MUST return unified `VerificationResult`:

```json
{
  "ok": true,
  "status": "ok",
  "violations": [],
  "policyId": "optional",
  "stateHash": "optional",
  "auditHeadHash": "optional"
}
```

Status enum:

- `ok`
- `invalid`
- `inconclusive`

Violations MUST be deterministically sorted by:

1. `code` (lexicographic)
2. `index` (missing treated as `0`)

`inconclusive` is reserved for traces that are structurally valid but not strictly anchor-complete (for example: no `STATE_CHECKPOINT` when strict anchors are required).

---

## 11. Verification Envelope (V1)

`VerificationEnvelopeV1` logical structure:

- `formatVersion: 1`
- `snapshot: Uint8Array`
- `events: AuditEvent[]`

Wire format JSON:

```json
{
  "formatVersion": 1,
  "snapshot": "<base64 of CanonicalState bytes>",
  "events": []
}
```

Wire bytes MUST be `utf8(canonicalJson(envelope_wire))`.

`decodeEnvelope` MUST reject malformed schema:
- missing/unsupported `formatVersion`
- non-string `snapshot`
- non-array `events`
- non-object entries in `events`

### Example Envelope JSON

```json
{
  "formatVersion": 1,
  "snapshot": "eyJmb3JtYXRWZXJzaW9uIjoxLCJlbmdpbmVWZXJzaW9uIjoiMS4wLjEiLCJwb2xpY3lJZCI6IjY1ODZjMTNiZDhmYTRlOWRlODdkNGM4NGNhOGVmZGI3Njc3ZTBhMzk3NjA5YmQ5ZGVkN2VlOWVmMDQ4Mjc0ZGUiLCJtb2R1bGVzIjp7fX0=",
  "events": [
    {
      "type": "INTENT_RECEIVED",
      "intent_hash": "0378394eb990e096126013b090ac3271c9368074477f58d46f03ba18e1aa7510",
      "agent_id": "agent-1",
      "timestamp": 1772718102,
      "policyId": "6586c13bd8fa4e9de87d4c84ca8efdb7677e0a397609bd9ded7ee9ef048274de"
    }
  ]
}
```

---

## 12. Verifier Semantics

## 12.1 `verifySnapshot`

MUST:
- decode canonical snapshot bytes
- enforce `formatVersion == 1`
- require non-empty `policyId`
- hash each `modules[moduleId]` payload with sorted module IDs
- compute `stateHash` from canonical object:
  - `formatVersion`
  - `engineVersion`
  - `policyId`
  - `modules: { moduleId -> moduleHash }`

## 12.2 `verifyAuditEvents`

MUST:
- validate each event shape (`object`, finite `timestamp`)
- enforce non-decreasing timestamps
- recompute `auditHeadHash` using chain algorithm
- enforce policy binding rules:
  - if `expectedPolicyId` is set, each event MUST carry matching `policyId`
  - mixed non-null policy IDs are invalid
- in strict mode (or `requireStateAnchors=true`), absence of a valid checkpoint anchor yields `inconclusive` with `NO_STATE_ANCHOR`

## 12.3 `verifyEnvelope`

MUST:
- decode envelope
- run `verifySnapshot` on `snapshot`
- run `verifyAuditEvents` on `events`
- enforce snapshot `policyId` equals audit inferred `policyId` (when both available)
- merge violations with deterministic ordering
- propagate `policyId`, `stateHash`, and `auditHeadHash`

Status resolution:
- `invalid` if any invalid condition exists
- `inconclusive` if no invalid condition exists but strict anchor condition is unmet
- `ok` otherwise

---

## 13. Determinism Constraints

Compliant implementations MUST NOT introduce hidden entropy in protocol paths.

Disallowed in deterministic evaluation/verification:
- wall-clock reads not supplied as explicit input
- random number generation
- non-deterministic iteration order in hashed objects
- locale-dependent formatting
- floating-point non-finite values in canonicalized data

Strict mode MUST fail closed when required deterministic inputs (for example `now`) are missing.  
Best-effort mode MAY continue but MUST preserve deterministic processing over provided inputs.

---

## 14. Compatibility and Versioning

- v1.0.2 is patch-compatible with v1.0.0 and v1.0.1 protocol semantics.
- `formatVersion` governs wire/schema compatibility.
- Changing `formatVersion` is breaking and requires a new major protocol version.
- Adding optional fields that do not alter existing canonicalized semantics is non-breaking.
- Changing canonicalization rules, hash input ordering, or verifier status semantics is breaking.
- Unknown future `formatVersion` values MUST be rejected.

---

## 15. Conformance and Test Vectors

A third-party implementation is conformant if it reproduces protocol outputs on the official vectors, including:

- intent hashes
- authorization payload/signature-linked fields
- snapshot bytes/hashes
- audit chain heads
- envelope verification statuses/violations

Conformance suites MUST check deterministic equivalence, including:
- key-order insensitivity in canonical hashing
- snapshot roundtrip idempotence
- deterministic violation ordering
- replay/verification consistency across processes/runtimes

DelegationV1 conformance (v1.3+) additionally requires:
- `delegation_parent_hash = SHA256(canonical_json(AuthorizationV1))` - key-order invariant
- `verifyDelegation()` field/structural checks - no crypto required
- `verifyDelegationChain()` - hash recomputation, chain structural checks
- Ed25519 signature path - via test key material in `opts.trustedKeySets`

Reference vectors are distributed in `@oxdeai/conformance`.

---

## 16. Implementation Notes

- `@oxdeai/core` is the TypeScript reference implementation.
- Equivalent implementations in Rust/Go/Python MUST follow this protocol text and conformance vectors.
- Where field naming differs in implementation-specific APIs, canonical semantics in this spec are authoritative.
