// SPDX-License-Identifier: Apache-2.0
/**
 * policy.ts — Policy Decision Point (PDP)
 *
 * Mirrors examples/openai-tools with the same economic scenario.
 * LangGraph proposes actions; OxDeAI decides whether they may execute.
 */

import { PolicyEngine } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";

export const GPU_COST: Record<string, Record<string, bigint>> = {
  a100: { "us-east-1": 500n },
  h100: { "us-east-1": 900n },
};

export function gpuCost(asset: string, region: string): bigint {
  const cost = GPU_COST[asset]?.[region];
  if (cost === undefined) throw new Error(`Unknown GPU cost: ${asset}/${region}`);
  return cost;
}

export const POLICY_ID =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

export const AGENT_ID = "gpu-agent-1";

const _engineSecret = process.env.OXDEAI_ENGINE_SECRET ?? "";
if (!_engineSecret) throw new Error("Missing required env var: OXDEAI_ENGINE_SECRET");

export const engine = new PolicyEngine({
  policy_version: "v1.0.0",
  engine_secret: _engineSecret,
  authorization_ttl_seconds: 60,
  policyId: POLICY_ID,
});

export function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "period-demo",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PROVISION"],
      assets: ["a100"],
      targets: ["us-east-1"],
    },
    budget: {
      budget_limit: { [AGENT_ID]: 1_000n },
      spent_in_period: { [AGENT_ID]: 0n },
    },
    max_amount_per_action: { [AGENT_ID]: 500n },
    velocity: {
      config: { window_seconds: 3600, max_actions: 100 },
      counters: {},
    },
    replay: {
      window_seconds: 3600,
      max_nonces_per_agent: 256,
      nonces: {},
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

let nonceCounter = 1n;

export function buildProvisionIntent(
  asset: string,
  region: string,
  timestampSeconds: number
): Extract<Intent, { type?: "EXECUTE" }> {
  const nonce = nonceCounter++;
  const amount = gpuCost(asset, region);
  return {
    intent_id: `intent-gpu-${nonce}`,
    agent_id: AGENT_ID,
    action_type: "PROVISION",
    type: "EXECUTE",
    amount,
    asset,
    target: region,
    timestamp: timestampSeconds,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "agent-sig-placeholder",
    tool: "provision_gpu",
    tool_call: true,
    depth: 0,
  };
}
