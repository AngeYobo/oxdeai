/**
 * scenario.ts - Deterministic demo scenario runner.
 *
 * Runs two charge_wallet proposals through the real OxDeAI engine:
 *   1. charge_wallet(user_123, 10) → ALLOW  (nonce 42: fresh)
 *   2. charge_wallet(user_123, 10) → DENY   (nonce 42: already recorded - REPLAY_DETECTED)
 *
 * Returns structured step data consumed by the UI.
 * The engine does real policy evaluation - no mocked decisions.
 */

import type { Authorization, State } from "@oxdeai/core";
import { OxDeAIGuard, OxDeAIDenyError } from "@oxdeai/guard";
import { engine, makeState, buildChargeIntent, AGENT_ID, WALLET_START } from "./policy.js";

// ── Step types ────────────────────────────────────────────────────────────────

export type AgentStepType = "thought" | "propose" | "execute" | "blocked";

export interface AgentLogEntry {
  type: AgentStepType;
  label: string;
  detail?: string;
}

export interface AuthDecision {
  tool: string;
  args: Record<string, string | number>;
  stateSnapshot: Record<string, string | number | boolean>;
  policyCheck: string;
  decision: "ALLOW" | "DENY";
  reason: string;
  authId?: string;
}

export interface ScenarioStep {
  agent: AgentLogEntry;
  auth?: AuthDecision;
  /** State chip values to update after this step renders */
  stateAfter?: {
    walletBalance: string;
    alreadyCharged: boolean;
  };
}

// ── Scenario runner ───────────────────────────────────────────────────────────

export async function runScenario(): Promise<ScenarioStep[]> {
  const steps: ScenarioStep[] = [];
  let state: State = makeState();
  const ts = Math.floor(Date.now() / 1000);

  // ── Step 1: Agent receives task ──────────────────────────────────────────
  steps.push({
    agent: {
      type: "thought",
      label: "Task received",
      detail: "Charge user_123 wallet 10 units for completed order #42",
    },
  });

  // ── Step 2: First proposal - expect ALLOW ────────────────────────────────
  let firstDecision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let firstReason = "unknown";
  let firstAuthId: string | undefined;

  const guard1 = OxDeAIGuard({
    engine,
    getState: () => state,
    setState: (s: State) => { state = s; },
    // Use a fixed intent so the nonce is deterministic for both calls
    mapActionToIntent: () => buildChargeIntent(ts),
    beforeExecute(_action: unknown, authorization: Authorization) {
      firstAuthId = authorization.authorization_id;
      firstDecision = "ALLOW";
      firstReason = "balance sufficient · nonce 42 not yet recorded";
    },
  });

  try {
    await guard1(
      { name: "charge_wallet", args: { user: "user_123", amount: 10 }, context: { agent_id: AGENT_ID } },
      async () => "charge-receipt-001"
    );
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      const reasons = [...(err as OxDeAIDenyError).reasons];
      firstDecision = "DENY";
      firstReason = reasons.join(", ");
    } else {
      throw err;
    }
  }

  steps.push({
    agent: {
      type: "propose",
      label: "Proposing charge_wallet(user_123, 10)",
      detail: "intent_id: charge-user123-order42 · nonce: 42",
    },
    auth: {
      tool: "charge_wallet",
      args: { user: "user_123", amount: 10 },
      stateSnapshot: {
        wallet_balance: `${WALLET_START}.00`,
        nonce_42_used: false,
        agent_budget_remaining: "ample",
      },
      policyCheck: "action_type: ✓ · allowlist: ✓ · nonce_fresh: ✓",
      decision: firstDecision,
      reason: firstReason,
      authId: firstAuthId,
    },
  });

  // ── Step 3: Execution (side effect) ─────────────────────────────────────
  if (firstDecision === "ALLOW") {
    steps.push({
      agent: {
        type: "execute",
        label: "Execution: wallet charged 10 units",
        detail: "receipt: charge-receipt-001 · side effect committed",
      },
      stateAfter: {
        walletBalance: `${WALLET_START - 10}.00`,
        alreadyCharged: true,
      },
    });
  }

  // ── Step 4: Agent uncertainty / retry ────────────────────────────────────
  steps.push({
    agent: {
      type: "thought",
      label: "Network timeout - uncertain if charge completed",
      detail: "Agent retries same action with the same intent_id and nonce",
    },
  });

  // ── Step 5: Second proposal - expect DENY (replay) ──────────────────────
  let secondDecision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let secondReason = "unknown";

  const guard2 = OxDeAIGuard({
    engine,
    getState: () => state,
    setState: (s: State) => { state = s; },
    mapActionToIntent: () => buildChargeIntent(ts + 1), // ts+1, same nonce
    beforeExecute() {
      secondDecision = "ALLOW"; // should not be reached
      secondReason = "unexpectedly allowed";
    },
  });

  try {
    await guard2(
      { name: "charge_wallet", args: { user: "user_123", amount: 10 }, context: { agent_id: AGENT_ID } },
      async () => "charge-receipt-002" // never called on DENY
    );
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      const reasons = [...(err as OxDeAIDenyError).reasons];
      secondDecision = "DENY";
      secondReason = reasons.join(", ");
    } else {
      throw err;
    }
  }

  steps.push({
    agent: {
      type: "propose",
      label: "Proposing charge_wallet(user_123, 10) [retry]",
      detail: "Same intent_id: charge-user123-order42 · same nonce: 42",
    },
    auth: {
      tool: "charge_wallet",
      args: { user: "user_123", amount: 10 },
      stateSnapshot: {
        wallet_balance: `${WALLET_START - 10}.00`,
        nonce_42_used: true, // recorded after first ALLOW
        agent_budget_remaining: "ample",
      },
      policyCheck: "action_type: ✓ · allowlist: ✓ · nonce_fresh: ✗ (already recorded)",
      decision: secondDecision,
      reason: secondReason,
    },
  });

  // ── Step 6: Blocked ──────────────────────────────────────────────────────
  steps.push({
    agent: {
      type: "blocked",
      label: "Blocked at authorization boundary",
      detail: `Execution did not occur · wallet balance: ${WALLET_START - 10}.00 (charged exactly once)`,
    },
    stateAfter: {
      walletBalance: `${WALLET_START - 10}.00`,
      alreadyCharged: true,
    },
  });

  return steps;
}
