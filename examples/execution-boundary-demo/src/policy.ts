/**
 * policy.ts - Engine + state setup for the execution boundary demo.
 *
 * Scenario: an agent charges a user wallet.
 * Both calls use the same nonce (42n) so the second call triggers REPLAY_DETECTED.
 * Budget is ample - replay protection is the limiting control, not spend limits.
 */

import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

export const POLICY_ID =
  "demo-execution-boundary-0000000000000000000000000000000000000000000000";

export const AGENT_ID = "payment-agent-1";

// Fixed nonce - both proposals use this value so the retry triggers replay detection.
export const CHARGE_NONCE = 42n;

// 10 units * 1_000_000 micro-units (matching defaultNormalizeAction convention)
export const CHARGE_AMOUNT = 10_000_000n;

// Starting wallet display balance (domain concept, separate from engine budget)
export const WALLET_START = 100;

export const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: "demo-secret-replace-in-production",
  authorization_ttl_seconds: 60,
  policyId: POLICY_ID,
});

export function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "demo-period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PAYMENT"],
      assets: ["wallet"],
      targets: ["user_123"],
    },
    budget: {
      // Ample budget - not the limiting factor in this demo
      budget_limit: { [AGENT_ID]: 1_000_000_000n },
      spent_in_period: { [AGENT_ID]: 0n },
    },
    max_amount_per_action: { [AGENT_ID]: 100_000_000n },
    velocity: {
      config: { window_seconds: 3600, max_actions: 100 },
      counters: {},
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {}, // nonce 42 will be recorded here after the first ALLOW
    },
    concurrency: {
      max_concurrent: { [AGENT_ID]: 5 },
      active: {},
      active_auths: {},
    },
    recursion: { max_depth: { [AGENT_ID]: 5 } },
    tool_limits: {
      window_seconds: 3600,
      max_calls: { [AGENT_ID]: 100 },
      calls: {},
    },
  };
}

export function buildChargeIntent(
  timestampSeconds: number
): Extract<Intent, { type?: "EXECUTE" }> {
  return {
    type: "EXECUTE",
    intent_id: "charge-user123-order42",
    agent_id: AGENT_ID,
    action_type: "PAYMENT",
    amount: CHARGE_AMOUNT,
    asset: "wallet",
    target: "user_123",
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce: CHARGE_NONCE, // same nonce for both calls - enables replay detection on retry
    signature: "agent-sig-placeholder",
    tool: "charge_wallet",
    tool_call: true,
    depth: 0,
  };
}
