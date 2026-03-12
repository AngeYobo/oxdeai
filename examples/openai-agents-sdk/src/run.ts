import { pathToFileURL } from "node:url";
import {
  encodeCanonicalState,
  encodeEnvelope,
  verifyEnvelope,
  verifySnapshot,
} from "@oxdeai/core";
import type { State } from "@oxdeai/core";
import { AGENT_ID, engine, makeState, POLICY_ID } from "./policy.js";
import { guardedProvision } from "./pep.js";
import { proposeCallsViaOpenAIAgents } from "./agents.js";

export async function runDemo(log: (msg: string) => void = (msg) => console.log(msg)): Promise<void> {
  const decisions: string[] = [];

  log("╔══════════════════════════════════════════════════════════════════╗");
  log("║  OxDeAI — OpenAI Agents SDK Boundary Demo                       ║");
  log("║  Scenario: GPU provisioning — budget for exactly 2 calls        ║");
  log("╚══════════════════════════════════════════════════════════════════╝");
  log(`\nAgent:   ${AGENT_ID}`);
  log("Policy:  budget=1000 minor units  max_per_action=500  (2× a100 allowed)");
  log("Source:  tool proposals from OpenAI Agents SDK flow");

  const baseTimestamp = Math.floor(Date.now() / 1000);
  let state: State = makeState();
  let callIndex = 0;
  let allowedCount = 0;
  let deniedCount = 0;

  const plannedCalls = await proposeCallsViaOpenAIAgents(log);

  log("\n── Agent proposals (from OpenAI Agents SDK) ───────────────────────");
  for (const call of plannedCalls) {
    const timestamp = baseTimestamp + callIndex;
    const result = guardedProvision(call.asset, call.region, state, timestamp, log);

    if (result.allowed) {
      decisions.push("ALLOW");
      allowedCount++;
      state = result.nextState;
      const spent = state.budget.spent_in_period[AGENT_ID] ?? 0n;
      const limit = state.budget.budget_limit[AGENT_ID] ?? 0n;
      log(`   budget after: ${spent}/${limit} minor units spent`);
    } else {
      decisions.push("DENY");
      deniedCount++;
    }
    callIndex++;
  }

  log("\n── Summary ──────────────────────────────────────────────────────────");
  log(`   Allowed: ${allowedCount}   Denied: ${deniedCount}`);

  const auditEvents = engine.audit.snapshot();
  log(`\n── Audit events (${auditEvents.length}) ──────────────────────────────────────────`);
  for (const event of auditEvents) {
    const e = event as Record<string, unknown>;
    const type = String(e["type"] ?? "UNKNOWN");
    const ts = String(e["timestamp"] ?? "?");
    const ih = e["intent_hash"] as string | undefined;
    const dec = e["decision"] as string | undefined;
    const detail = ih ? `  intent=${ih.slice(0, 16)}...` : "";
    const decStr = dec ? `  decision=${dec}` : "";
    log(`   [${ts}] ${type}${detail}${decStr}`);
  }

  log("\n── Snapshot ─────────────────────────────────────────────────────────");
  const canonicalState = engine.exportState(state);
  const snapshotBytes = encodeCanonicalState(canonicalState);
  const snapResult = verifySnapshot(snapshotBytes, { expectedPolicyId: POLICY_ID });
  if (snapResult.status !== "ok" || !snapResult.stateHash) {
    throw new Error(`Snapshot verification failed: ${snapResult.status}`);
  }
  log(`   stateHash: ${snapResult.stateHash.slice(0, 32)}...`);
  log(`   size:      ${snapshotBytes.length} bytes`);

  log("\n── Verification envelope ────────────────────────────────────────────");
  const eventsWithCheckpoint = [
    ...auditEvents,
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: snapResult.stateHash,
      timestamp: baseTimestamp + callIndex,
      policyId: POLICY_ID,
    },
  ];

  const envelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: eventsWithCheckpoint,
  });
  log(`   Envelope size: ${envelopeBytes.length} bytes`);

  log("\n── verifyEnvelope (strict mode) ─────────────────────────────────────");
  const vr = verifyEnvelope(envelopeBytes, {
    expectedPolicyId: POLICY_ID,
    mode: "strict",
  });

  log(`   status:        ${vr.status}`);
  log(`   policyId:      ${(vr.policyId ?? "—").slice(0, 32)}...`);
  log(`   stateHash:     ${(vr.stateHash ?? "—").slice(0, 32)}...`);
  log(`   auditHeadHash: ${(vr.auditHeadHash ?? "—").slice(0, 32)}...`);
  log(`   violations:    ${vr.violations.length === 0 ? "none" : JSON.stringify(vr.violations)}`);

  if (vr.status !== "ok") {
    throw new Error(`Envelope verification failed: ${vr.status}`);
  }

  log("\n── Cross-adapter demo scenario ──────────────────────────────────────");
  decisions.forEach((decision, index) => {
    log(`   decision ${index + 1}: ${decision}`);
  });
  log(`   verifyEnvelope() => ${vr.status}`);

  log("\n✓ Verification passed.");
}

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) {
  runDemo().catch((err) => {
    console.error("\n✗ Demo failed:", err);
    process.exit(1);
  });
}
