# OxDeAI SPEC (Developer Companion, Non-Normative)

This document is an implementation and integration companion to the OxDeAI protocol specification.

- **Normative source of truth:** `PROTOCOL.md` / `protocol/protocol.md`
- This file is **non-normative** and explains rationale, patterns, and practical guidance.
- If any statement here conflicts with the protocol spec, **the protocol spec wins**.

---

## 1) Why Pre-Execution Economic Containment

Traditional observability is post-fact:
- detect anomaly
- alert operator
- respond after damage

OxDeAI is pre-execution:
- evaluate intent against policy state
- allow or deny before side effects
- emit verifiable artifacts

This shifts control from:
- **“detect and react”**  
to
- **“verify and gate”**

Practical effect:
- budget overruns are blocked, not merely observed
- replay/duplication is rejected before execution
- concurrency and recursion risks are bounded by policy, not dashboards

---

## 2) System Boundary

```text
+---------------------------+      +-----------------------+      +-----------------------------+
| Agent / Runtime / Orchestrator | -> | OxDeAI Policy Engine | -> | Tools / Payments / Infra APIs |
+---------------------------+      +-----------------------+      +-----------------------------+
               |                               |
               |                               +--> Canonical Snapshot
               |                               +--> Audit Events (hash-chained)
               |                               +--> Authorization (ALLOW only)
               |
               +--> persists state/audit + forwards envelope for offline verification
```

Boundary rule of thumb:
- Side effects (tool call, spend, provisioning) MUST happen only after `ALLOW`.

---

## 3) Happy Path Sequence

## 3.1 Deterministic evaluation

1. Runtime loads current policy `state`.
2. Runtime builds `intent`.
3. Runtime calls `evaluatePure(intent, state)` (or `evaluate(...)` if using mutating commit path).
4. Engine returns:
   - `DENY` with reasons, or
   - `ALLOW` + `authorization` + `nextState`.

## 3.2 Commit and execute

On `ALLOW`:

1. Persist `nextState` atomically.
2. Persist emitted audit events in order.
3. Execute external side effect (tool/payment/infra).
4. Optionally append execution attestation event.

On `DENY`:

1. Persist audit events.
2. Do not execute side effect.
3. Return deny reason(s) upstream.

---

## 4) Offline Verification Flow

Typical auditor flow:

```text
Producer runtime
  -> exports VerificationEnvelopeV1 (snapshot + events)
  -> sends envelope bytes to auditor/verifier

Auditor
  -> runs verifyEnvelope(envelopeBytes)
  -> gets VerificationResult { status, violations, policyId, stateHash, auditHeadHash }
  -> stores report / compliance evidence
```

What this enables:
- independent replay-grade verification without running the live engine runtime
- deterministic evidence sharing across org boundaries

---

## 5) Failure Handling Matrix

| Result | Meaning | Recommended Runtime Action |
|---|---|---|
| `DENY` (evaluation) | Policy rejected intent | Fail closed; do not execute side effect; return reasons |
| `invalid` (verification) | Artifact/trace malformed or inconsistent | Treat as security/compliance failure; reject artifact |
| `inconclusive` (verification) | Structurally valid but insufficient strict anchors | Do not auto-approve; escalate/manual review or best-effort policy |
| `ok` (verification) | Artifact verifies under selected mode | Accept/report as verified |

Operational policy tip:
- strict environments SHOULD treat `inconclusive` as non-pass for settlement/compliance decisions.

---

## 6) Recommended v1 Module Set

Recommended baseline module set for production containment:

- `BudgetModule`
- `VelocityModule`
- `ConcurrencyModule`
- `ReplayModule`
- `RecursionDepthModule`
- `KillSwitchModule`
- `ToolAmplificationModule`
- `AllowlistModule`

Why this set:
- spend control (`Budget`, per-action caps)
- rate/loop control (`Velocity`, `ToolAmplification`, `RecursionDepth`)
- duplication resistance (`Replay`)
- blast-radius control (`Concurrency`)
- emergency stop (`KillSwitch`)
- explicit surface restriction (`Allowlist`)

## 6.1 Extending with custom modules

Custom modules should:
1. Consume only explicit `(intent, workingState)` input.
2. Return deterministic `ALLOW/DENY` + optional `stateDelta`.
3. Avoid hidden entropy (no random/system time reads inside module logic).
4. Define canonical state slice serialization if snapshot hashing includes the module.

---

## 7) State Persistence Patterns

## 7.1 Atomic commit

Persist state with atomic write pattern:
- write temp file / transaction row
- fsync/commit
- rename/commit pointer

Never partially overwrite live state.

## 7.2 Idempotency keys

Use `intent_id` / `nonce` as idempotency keys at runtime boundaries.
- repeated delivery should not duplicate side effects.

## 7.3 WAL or append-first strategy

For robust recovery:
- append audit event(s) first or in same transaction boundary as state commit
- on crash, recover by replaying committed audit/state logs

## 7.4 Crash recovery

On restart:
1. load last committed state
2. verify audit chain integrity
3. reconcile pending executions against authorization IDs and local execution ledger

---

## 8) Clock and Time Guidance

Time-sensitive controls include:
- authorization expiry
- velocity windows
- replay windows

Recommendations:
1. Use monotonic non-decreasing runtime timestamps for event emission.
2. Define drift tolerance policy at system boundary (e.g., max accepted skew).
3. In strict deterministic contexts, inject `now` explicitly; avoid implicit wall clock reads in verification/evidence pipelines.
4. Keep replay window and velocity window parameters explicit in state/policy.

---

## 9) Security Guidance

## 9.1 Secret key custody

- Engine signing secret MUST be protected (KMS/HSM or equivalent).
- Never embed long-lived secrets in client-side or untrusted runtime surfaces.

## 9.2 Rotation strategy

- Support key rotation with planned overlap period.
- Record key metadata externally (or via key-id mapping) for historical verification.

## 9.3 Key IDs

Even if current artifact carries only signature, deployments SHOULD maintain key-id association in runtime metadata or audit context for operational debugging and rotation traceability.

## 9.4 Multi-tenant isolation

Per tenant/environment:
- isolate policy state
- isolate signing keys
- isolate audit streams
- isolate authorization namespaces

Never share mutable state buckets across tenants.

---

## 10) Integration Guidance

Minimal runtime loop:

1. Load state.
2. Build intent.
3. Evaluate.
4. If ALLOW:
   - persist nextState + audit
   - execute side effect
5. If DENY:
   - persist audit
   - reject request
6. Periodically package snapshot + audit into envelope for external verification.

This keeps execution gating deterministic while preserving independent auditability.

---

## 11) Practical Notes

- Keep protocol-facing serialization canonical from day one.
- Treat verification outputs as first-class operational signals.
- Keep module ordering fixed and explicit.
- Avoid introducing non-deterministic dependencies in policy-critical path.
- Use conformance vectors to validate non-TypeScript implementations (Go/Rust/Python).