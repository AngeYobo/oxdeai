// SPDX-License-Identifier: Apache-2.0
/**
 * run.ts - Demo entry point
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

import { pathToFileURL } from "node:url";
import {
  encodeCanonicalState,
  encodeEnvelope,
  verifySnapshot,
  verifyEnvelope,
} from "@oxdeai/core";
import type { KeySet, State } from "@oxdeai/core";
import { engine, POLICY_ID, AGENT_ID, makeState } from "./policy.js";
import { guardedProvision } from "./pep.js";

// ── ANSI color helpers ────────────────────────────────────────────────────────
const C = {
  reset:      "\x1b[0m",
  bold:       "\x1b[1m",
  dim:        "\x1b[2m",
  // foreground
  cyan:       "\x1b[36m",
  green:      "\x1b[32m",
  red:        "\x1b[31m",
  yellow:     "\x1b[33m",
  blue:       "\x1b[34m",
  magenta:    "\x1b[35m",
  white:      "\x1b[97m",
  // bold shortcuts
  bCyan:      "\x1b[1;36m",
  bGreen:     "\x1b[1;32m",
  bRed:       "\x1b[1;31m",
  bYellow:    "\x1b[1;33m",
  bWhite:     "\x1b[1;97m",
  bMagenta:   "\x1b[1;35m",
};

const c = (color: string, text: string) => `${color}${text}${C.reset}`;

const DEMO_TRUSTED_KEYSET: KeySet = {
  issuer: "oxdeai.policy-engine",
  version: "1",
  keys: [
    {
      kid: "2026-01",
      alg: "Ed25519",
      public_key: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWiMMGTYK7zzHwZXLzDpCshxAH6Lgx8gVsJaixePuY7g=
-----END PUBLIC KEY-----`,
    },
  ],
};

// ── Planned calls (simulates OpenAI tool-call proposals) ──────────────────────

const PLANNED_CALLS = [
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" },
  { asset: "a100", region: "us-east-1" }, // will be DENIED - budget exhausted
];

// Stable demo timestamp - no Date.now(), output is fully deterministic.
const DEMO_BASE_TIMESTAMP = 1_700_000_000; // 2023-11-14T22:13:20Z

// ── Run 1: Live authorization demo ────────────────────────────────────────────

export async function runDemo(
  log: (msg: string) => void = (msg) => console.log(msg)
): Promise<{ envelopeBytes: Uint8Array }> {
  const decisions: string[] = [];

  if (!process.env.OXDEAI_ENGINE_SECRET) {
    log(c(C.dim, "(using built-in demo engine secret; no setup required)"));
  }

  log(c(C.cyan, "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan, "║") + c(C.bWhite, "  OxDeAI - Pre-Execution Authorization Demo  (Run 1: live)       ") + c(C.cyan, "║"));
  log(c(C.cyan, "║") + c(C.dim,    "  Scenario: GPU provisioning - budget for exactly 2 proposals     ") + c(C.cyan, "║"));
  log(c(C.cyan, "╚══════════════════════════════════════════════════════════════════╝"));

  log(`\n${c(C.dim, "Agent:")}   ${c(C.bCyan, AGENT_ID)}`);
  log(`${c(C.dim, "Policy:")}  budget=${c(C.yellow, "1000")} minor units  max_per_action=${c(C.yellow, "500")}  (2× a100 allowed)`);

  // ── State setup ──────────────────────────────────────────────────────────
  let state: State = makeState();
  let callIndex = 0;

  let allowedCount = 0;
  let deniedCount  = 0;

  // ── Agent proposal loop ──────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Agent proposals ─────────────────────────────────────────────────")}`);

  for (const call of PLANNED_CALLS) {
    const timestamp = DEMO_BASE_TIMESTAMP + callIndex;

    const result = guardedProvision(call.asset, call.region, state, timestamp, log);

    if (result.allowed) {
      decisions.push("ALLOW");
      allowedCount++;
      state = result.nextState;

      const spent = state.budget.spent_in_period[AGENT_ID] ?? 0n;
      const limit = state.budget.budget_limit[AGENT_ID]    ?? 0n;
      log(`   ${c(C.dim, "budget after:")} ${c(C.yellow, `${spent}/${limit}`)} minor units spent`);
    } else {
      decisions.push("DENY");
      deniedCount++;
    }

    callIndex++;
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Summary ──────────────────────────────────────────────────────────")}`);
  decisions.forEach((decision, i) => {
    const col = decision === "ALLOW" ? c(C.bGreen, decision) : c(C.bRed, decision);
    log(`   proposal ${i + 1}: ${col}`);
  });
  log(`   Allowed: ${c(C.bGreen, String(allowedCount))}   Denied: ${c(C.bRed, String(deniedCount))}`);

  // ── Audit chain (compact) ─────────────────────────────────────────────────
  const auditEvents = engine.audit.snapshot();
  log(`\n${c(C.dim, "── Audit chain ──────────────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "events:")}   ${auditEvents.length} hash-chained  ${c(C.dim, "(head hash verified in Run 2)")}`);

  // ── Snapshot ──────────────────────────────────────────────────────────────
  const canonicalState = engine.exportState(state);
  const snapshotBytes  = encodeCanonicalState(canonicalState);

  const snapResult = verifySnapshot(snapshotBytes, { expectedPolicyId: POLICY_ID });
  if (snapResult.status !== "ok" || !snapResult.stateHash) {
    throw new Error(`Snapshot verification failed: ${snapResult.status}`);
  }
  log(`\n${c(C.dim, "── Snapshot ─────────────────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "stateHash:")} ${c(C.blue, snapResult.stateHash.slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "size:")}      ${snapshotBytes.length} bytes`);

  // ── Build envelope ────────────────────────────────────────────────────────
  const eventsWithCheckpoint = [
    ...auditEvents,
    {
      type:      "STATE_CHECKPOINT" as const,
      stateHash: snapResult.stateHash,
      timestamp: DEMO_BASE_TIMESTAMP + callIndex,
      policyId:  POLICY_ID,
    },
  ];

  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events:   eventsWithCheckpoint,
  });

  log(`\n${c(C.dim, "── Envelope ─────────────────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "size:")} ${envelopeBytes.length} bytes  ${c(C.dim, "(ready for offline replay)")}`);

  log(`\n${c(C.bGreen, "✓ Run 1 complete.")}  Artifact produced - pass to Run 2 for replay verification.`);

  return { envelopeBytes };
}

// ── Run 2: Offline replay verification ────────────────────────────────────────

export async function runReplay(
  envelopeBytes: Uint8Array,
  log: (msg: string) => void = (msg) => console.log(msg)
): Promise<void> {
  log(`\n${c(C.cyan, "╔══════════════════════════════════════════════════════════════════╗")}`);
  log(`${c(C.cyan, "║")}${c(C.bWhite, "  OxDeAI - Offline Replay Verification       (Run 2: replay)   ")}${c(C.cyan, "║")}`);
  log(`${c(C.cyan, "║")}${c(C.dim,    "  No engine. No agent. Artifact-only - simulates a remote PEP.  ")}${c(C.cyan, "║")}`);
  log(`${c(C.cyan, "╚══════════════════════════════════════════════════════════════════╝")}`);

  log(`\n${c(C.dim, "  Input:")}   envelope from Run 1 (${envelopeBytes.length} bytes)`);
  log(`${c(C.dim,   "  Keyset:")}  issuer=${c(C.cyan, DEMO_TRUSTED_KEYSET.issuer)}  kid=${c(C.cyan, DEMO_TRUSTED_KEYSET.keys[0]?.kid ?? "?")}`);

  const vr = verifyEnvelope(envelopeBytes, {
    expectedPolicyId: POLICY_ID,
    mode: "strict",
    trustedKeySets: DEMO_TRUSTED_KEYSET,
  });

  const statusColor = vr.status === "ok" ? c(C.bGreen, vr.status) : c(C.bRed, vr.status);

  log(`\n${c(C.dim, "── Replay result ────────────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "status:")}        ${statusColor}`);
  log(`   ${c(C.dim, "policyId:")}      ${c(C.blue, (vr.policyId      ?? "-").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "stateHash:")}     ${c(C.blue, (vr.stateHash     ?? "-").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "auditHeadHash:")} ${c(C.blue, (vr.auditHeadHash ?? "-").slice(0, 32) + "...")}`);
  log(`   ${c(C.dim, "violations:")}    ${vr.violations.length === 0 ? c(C.bGreen, "none") : c(C.bRed, vr.violations.map((v) => v.code).join(", "))}`);

  if (vr.status !== "ok") {
    throw new Error(`Replay verification failed: ${vr.status}`);
  }

  log(`\n${c(C.bGreen, "✓ Replay passed.")}  Artifact verified independently - engine not involved.`);
  log("");
  log(`  ${c(C.bWhite, "What just happened:")}`);
  log(`  ${c(C.cyan, "┌─────────────────────────────────────────────────────────────────┐")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PDP")}  Run 1 evaluated each proposal before any tool ran.          ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}      Proposal 3 was ${c(C.bRed, "denied")} at the boundary - tool never ran.      ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PEP")}  Tool only executed after Authorization was confirmed.       ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}      No Authorization = no execution, even on ${c(C.bGreen, "ALLOW")}.             ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "REPLAY")}  Run 2 verified the artifact with no engine access.       ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}         Any party with the trusted keyset can replay offline.   ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "└─────────────────────────────────────────────────────────────────┘")}`);
}

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) {
  (async () => {
    const { envelopeBytes } = await runDemo();
    await runReplay(envelopeBytes);
  })().catch((err) => {
    console.error(`\n${"\x1b[1;31m"}✗ Demo failed:${"\x1b[0m"}`, err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
