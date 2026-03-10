import { createCanonicalState, encodeCanonicalState } from "@oxdeai/core";
import { PolicyEngine, signEnvelopeEd25519, encodeEnvelope, verifyAuthorization } from "@oxdeai/core";
import type { Intent, State, Authorization } from "@oxdeai/core";
import { generateKeyPairSync } from "node:crypto";

export function makeIntent(overrides: Partial<Intent> = {}): Intent {
  return {
    intent_id: "bench-intent-1",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    type: "EXECUTE",
    nonce: 1n,
    amount: 1000n,
    target: "merchant-1",
    timestamp: 1_700_000_000,
    metadata_hash: "0x" + "0".repeat(64),
    signature: "sig",
    depth: 0,
    tool_call: false,
    ...overrides
  } as Intent;
}

export function makeState(overrides: Partial<State> = {}): State {
  // Keep as compatible with internal state shape expected by PolicyEngine.
  const base = {
    policy_version: "0.1.0",
    period_id: "bench-period",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: ["USDC"], targets: ["merchant-1"] },
    budget: { budget_limit: { "agent-1": 1_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 10_000n },
    velocity: { config: { window_seconds: 60, max_actions: 1000 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 1024, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 100 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 10 } },
    tool_limits: { window_seconds: 60, max_calls: { "agent-1": 1000 }, calls: {} }
  } as State;

  return {
    ...base,
    ...overrides,
    kill_switch: { ...base.kill_switch, ...(overrides.kill_switch ?? {}) },
    budget: { ...base.budget, ...(overrides.budget ?? {}) },
    velocity: { ...base.velocity, ...(overrides.velocity ?? {}) },
    replay: { ...base.replay, ...(overrides.replay ?? {}) },
    concurrency: { ...base.concurrency, ...(overrides.concurrency ?? {}) },
    recursion: { ...base.recursion, ...(overrides.recursion ?? {}) },
    tool_limits: { ...base.tool_limits, ...(overrides.tool_limits ?? {}) }
  } as State;
}

export function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "0.1.0",
    engine_secret: "bench-secret",
    authorization_ttl_seconds: 60,
    authorization_issuer: "bench-issuer",
    authorization_audience: "bench-rp",
    policyId: "a".repeat(64)
  });
}

export function makeAuthorization(): Authorization {
  const engine = makeEngine();
  const intent = makeIntent();
  const state = makeState();
  const result = engine.evaluatePure(intent, state);
  if (result.decision !== "ALLOW") {
    throw new Error("bench fixture: expected allow authorization");
  }
  return result.authorization;
}

export function makeEnvelopeData(): { bytes: Uint8Array; publicKeyPem: string; trustedKeySet: any; policyId: string } {
  const keyPair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });

  const envelope = {
    formatVersion: 1,
    snapshot: encodeCanonicalState({ formatVersion: 1, engineVersion: "bench-engine", policyId: "bench-policy-id", modules: {} }),
    events: [],
    issuer: "bench-issuer",
    alg: "Ed25519",
    kid: "bench-key"
  } as any;

  const signed = signEnvelopeEd25519(envelope, { issuer: "bench-issuer", kid: "bench-key", privateKeyPem: keyPair.privateKey.toString() });
  const bytes = encodeEnvelope(signed);

  return {
    bytes,
    publicKeyPem: keyPair.publicKey.toString(),
    trustedKeySet: { issuer: "bench-issuer", version: "1", keys: [{ kid: "bench-key", alg: "Ed25519", public_key: keyPair.publicKey.toString() }] },
    policyId: "bench-policy-id"
  };
}
