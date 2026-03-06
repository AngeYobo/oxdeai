/**
 * run.ts — Demo entry point
 *
 * Simulates an agent proposing GPU provisioning calls.
 * OxDeAI enforces the economic boundary before each execution.
 *
 * Scenario (deterministic):
 *   Call 1: a100 / us-east-1 → ALLOW  (500 spent,  500 remaining)
 *   Call 2: a100 / us-east-1 → ALLOW  (1000 spent,   0 remaining)
 *   Call 3: a100 / us-east-1 → DENY   (BUDGET_EXCEEDED)
 *
 * Usage:
 *   node dist/run.js
 */

import {
  encodeCanonicalState,
  encodeEnvelope,
  verifySnapshot,
  verifyEnvelope,
} from "@oxdeai/core";
import type { State } from "@oxdeai/core";
import { engine, POLICY_ID, AGENT_ID, makeState } from "./policy.js";
import { guardedProvision } from "./pep.js";

// ── Planned calls (simulates OpenAI tool-call proposals) ──────────────────────

const PLANNED_CALLS = [
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" }, // will be DENIED — budget exhausted
];

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const log = (msg: string) => console.log(msg);

  log("╔══════════════════════════════════════════════════════════════════╗");
  log("║  OxDeAI — Pre-Execution Economic Boundary Demo                  ║");
  log("║  Scenario: GPU provisioning — budget for exactly 2 calls        ║");
  log("╚══════════════════════════════════════════════════════════════════╝");
  log(`\nAgent:   ${AGENT_ID}`);
  log(`Policy:  budget=1000 minor units  max_per_action=500  (2× a100 allowed)`);

  // ── State setup ─────────────────────────────────────────────────────────
  // Use wall-clock base + monotonic offset for deterministic timestamps.
  const baseTimestamp = Math.floor(Date.now() / 1000);
  let state: State = makeState();
  let callIndex = 0;

  let allowedCount = 0;
  let deniedCount  = 0;

  // ── Agent loop ───────────────────────────────────────────────────────────
  log("\n── Agent proposals ─────────────────────────────────────────────────");

  for (const call of PLANNED_CALLS) {
    const timestamp = baseTimestamp + callIndex; // monotonic, deterministic

    const result = guardedProvision(
      call.asset,
      call.region,
      state,
      timestamp,
      log
    );

    if (result.allowed) {
      allowedCount++;
      // Commit nextState from PDP — never mutate state directly.
      state = result.nextState;

      const spent     = state.budget.spent_in_period[AGENT_ID] ?? 0n;
      const limit     = state.budget.budget_limit[AGENT_ID]    ?? 0n;
      log(`   budget after: ${spent}/${limit} minor units spent`);
    } else {
      deniedCount++;
    }

    callIndex++;
  }

  log(`\n── Summary ──────────────────────────────────────────────────────────`);
  log(`   Allowed: ${allowedCount}   Denied: ${deniedCount}`);

  // ── Audit events ─────────────────────────────────────────────────────────
  const auditEvents = engine.audit.snapshot();
  log(`\n── Audit events (${auditEvents.length}) ──────────────────────────────────────────`);
  for (const event of auditEvents) {
    const e      = event as Record<string, unknown>;
    const type   = String(e["type"]        ?? "UNKNOWN");
    const ts     = String(e["timestamp"]   ?? "?");
    const ih     = e["intent_hash"] as string | undefined;
    const dec    = e["decision"]    as string | undefined;
    const detail = ih  ? `  intent=${ih.slice(0, 16)}...` : "";
    const decStr = dec ? `  decision=${dec}` : "";
    log(`   [${ts}] ${type}${detail}${decStr}`);
  }

  // ── Snapshot ──────────────────────────────────────────────────────────────
  log(`\n── Snapshot ─────────────────────────────────────────────────────────`);
  const canonicalState = engine.exportState(state);
  const snapshotBytes  = encodeCanonicalState(canonicalState);

  const snapResult = verifySnapshot(snapshotBytes, { expectedPolicyId: POLICY_ID });
  if (snapResult.status !== "ok" || !snapResult.stateHash) {
    throw new Error(`Snapshot verification failed: ${snapResult.status}`);
  }
  log(`   stateHash: ${snapResult.stateHash.slice(0, 32)}...`);
  log(`   size:      ${snapshotBytes.length} bytes`);

  // ── Verification envelope ─────────────────────────────────────────────────
  log(`\n── Verification envelope ────────────────────────────────────────────`);

  // Append STATE_CHECKPOINT so strict mode can anchor the chain.
  const eventsWithCheckpoint = [
    ...auditEvents,
    {
      type:      "STATE_CHECKPOINT" as const,
      stateHash: snapResult.stateHash,
      timestamp: baseTimestamp + callIndex,
      policyId:  POLICY_ID,
    },
  ];

  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events:   eventsWithCheckpoint,
  });
  log(`   Envelope size: ${envelopeBytes.length} bytes`);

  // ── Offline verification ──────────────────────────────────────────────────
  // Simulates a third-party auditor verifying without re-running the engine.
  log(`\n── verifyEnvelope (strict mode) ─────────────────────────────────────`);

  const vr = verifyEnvelope(envelopeBytes, {
    expectedPolicyId: POLICY_ID,
    mode: "strict",
  });

  log(`   status:        ${vr.status}`);
  log(`   policyId:      ${(vr.policyId      ?? "—").slice(0, 32)}...`);
  log(`   stateHash:     ${(vr.stateHash     ?? "—").slice(0, 32)}...`);
  log(`   auditHeadHash: ${(vr.auditHeadHash ?? "—").slice(0, 32)}...`);
  log(`   violations:    ${vr.violations.length === 0 ? "none" : JSON.stringify(vr.violations)}`);

  if (vr.status !== "ok") {
    throw new Error(`Envelope verification failed: ${vr.status}`);
  }

  log(`
✓ Verification passed.

  What just happened:
  ┌─────────────────────────────────────────────────────────────────                        ┐
  │ PDP  OxDeAI evaluated each intent before any tool ran.                                  │
  │      Call 3 was denied at the boundary — tool never touched.                            │
  │                                                                                         │
  │ PEP  Tool only executed after Authorization was confirmed.                              │
  │      No Authorization = no execution, even on ALLOW.                                    │
  │                                                                                         │
  │ AUDIT  ${auditEvents.length} hash-chained events record the full execution history.     │
  │                                                                                         │
  │ ENVELOPE  Independently verifiable without re-running the engine                        │
  └─────────────────────────────────────────────────────────────────                        ┘`);
}

main().catch((err) => {
  console.error("\n✗ Demo failed:", err);
  process.exit(1);
});