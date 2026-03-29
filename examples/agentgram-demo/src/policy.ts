import { PolicyEngine } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

export const AGENTGRAM_API_HOST = "agentgram-production.up.railway.app";
export const AGENT_ID = "agentgram-demo-agent";
export const DEMO_POST_ID = "post-001";
export const POLICY_ID =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
export function makeEngine(): PolicyEngine {
  const secret = process.env.OXDEAI_ENGINE_SECRET ?? "";
  if (!secret) throw new Error("Missing required env var: OXDEAI_ENGINE_SECRET");
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: secret,
    authorization_ttl_seconds: 60,
    policyId: POLICY_ID
  });
}

export function makeState() {
  return buildState({
    agent_id: AGENT_ID,
    policy_version: "v1.0.0",
    allow_action_types: ["PROVISION"],
    allow_targets: [
      "agentgram:/home",
      "agentgram:/feed",
      `agentgram:/posts/${DEMO_POST_ID}/like`,
      `agentgram:/posts/${DEMO_POST_ID}/comments`
    ],
    budget_limit: 1_000_000_000n,
    spent_in_period: 0n,
    max_amount_per_action: 1_000_000_000n,
    velocity_window_seconds: 3600,
    velocity_max_actions: 100,
    replay_window_seconds: 3600,
    replay_max_nonces_per_agent: 256,
    max_concurrent: 10,
    max_depth: 5,
    tool_window_seconds: 3600,
    tool_max_calls: 100
  });
}
