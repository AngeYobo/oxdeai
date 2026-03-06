/**
 * @oxdeai/conformance — Vector Extraction Script
 *
 * Generates frozen conformance vectors against @oxdeai/core@1.0.0.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import {
  sha256HexFromJson,
  encodeCanonicalState,
  decodeCanonicalState,
  verifySnapshot,
  verifyEnvelope,
  encodeEnvelope,
  PolicyEngine
} from "@oxdeai/core";
import type { Intent, State, Authorization } from "@oxdeai/core";
type ExecuteIntent = Extract<Intent, { type?: "EXECUTE" }>;
type EnvelopeEvent = Parameters<typeof encodeEnvelope>[0]["events"][number];

type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };
const BINDING_FIELDS = [
  "intent_id",
  "agent_id",
  "action_type",
  "depth",
  "amount",
  "asset",
  "target",
  "timestamp",
  "metadata_hash",
  "nonce",
  "type",
  "authorization_id",
  "tool",
  "tool_call"
] as const;

function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = canonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function sha256hexUtf8(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function writeVector(filename: string, data: object): void {
  const dir = path.resolve(process.cwd(), "vectors");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, filename),
    JSON.stringify(data, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2),
    "utf8"
  );
  console.log(`wrote ${filename}`);
}

const ENGINE_SECRET = "test-secret";

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: ENGINE_SECRET,
    authorization_ttl_seconds: 60,
    policyId: "a".repeat(64)
  });
}

function makeState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-1": 5_000_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 2_000_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 10 },
      counters: {}
    },
    replay: {
      window_seconds: 300,
      max_nonces_per_agent: 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 3 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 5 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 50 },
      calls: {}
    }
  };
}

function makeIntent(nonce: bigint, timestamp: number, extra?: Partial<ExecuteIntent>): ExecuteIntent {
  return {
    intent_id: `intent-${nonce.toString()}`,
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: 1_000_000n,
    target: "merchant-1",
    timestamp,
    metadata_hash: "0".repeat(64),
    nonce,
    signature: "sig-placeholder",
    depth: 0,
    tool: "openai.responses",
    tool_call: true,
    type: "EXECUTE",
    ...extra
  };
}

function authSigningPayload(auth: Authorization, policyId: string): Record<string, JsonValue> {
  return {
    expires_at: auth.expires_at,
    intent_hash: auth.intent_hash,
    policy_id: policyId,
    state_hash: auth.state_snapshot_hash
  };
}

function bindingIntentProjection(intent: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of BINDING_FIELDS) {
    if (intent[key] !== undefined) out[key] = intent[key];
  }
  return out;
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function extractIntentHash(): Promise<void> {
  const base = makeIntent(42n, 1730000000);
  const reordered = {
    tool_call: base.tool_call,
    tool: base.tool,
    depth: base.depth,
    nonce: base.nonce,
    timestamp: base.timestamp,
    target: base.target,
    amount: base.amount,
    action_type: base.action_type,
    agent_id: base.agent_id,
    metadata_hash: base.metadata_hash,
    intent_id: base.intent_id,
    type: base.type,
    signature: base.signature
  } as ExecuteIntent;
  const withExtra = { ...base, _internal_trace_id: "ignored" };

  const h1 = sha256HexFromJson(bindingIntentProjection(base));
  const h2 = sha256HexFromJson(bindingIntentProjection(reordered));
  const h3 = sha256HexFromJson(bindingIntentProjection(withExtra as Record<string, unknown>));

  writeVector("intent-hash.json", {
    version: "1.0.0",
    vectors: [
      { id: "intent-hash-001", input: base, expected: { hash: h1 } },
      { id: "intent-hash-002", input: reordered, expected: { hash: h2 }, invariant: "equals intent-hash-001" },
      {
        id: "intent-hash-003",
        input: withExtra,
        binding_fields: [...BINDING_FIELDS],
        expected: { hash: h3 },
        invariant: "equals intent-hash-001"
      }
    ]
  });
}

async function extractAuthorizationPayload(): Promise<void> {
  const engine = makeEngine();
  const state = makeState();
  const policyId = engine.computePolicyId();

  const r1 = engine.evaluatePure(makeIntent(100n, 1730000000), state);
  if (r1.decision !== "ALLOW") throw new Error("expected ALLOW for auth vector 1");

  const r2 = engine.evaluatePure(makeIntent(101n, 0), makeState());
  if (r2.decision !== "ALLOW") throw new Error("expected ALLOW for auth vector 2");

  writeVector("authorization-payload.json", {
    version: "1.0.0",
    ttl_seconds: 60,
    signing_algorithm: "HMAC-SHA256",
    vectors: [
      {
        id: "auth-payload-001",
        input: makeIntent(100n, 1730000000),
        expected: {
          intent_hash: r1.authorization.intent_hash,
          policy_id: policyId,
          state_hash: r1.authorization.state_snapshot_hash,
          expires_at: r1.authorization.expires_at,
          canonical_signing_payload: canonicalJson(authSigningPayload(r1.authorization, policyId)),
          signature: r1.authorization.engine_signature
        }
      },
      {
        id: "auth-payload-002",
        input: makeIntent(101n, 0),
        expected: {
          intent_hash: r2.authorization.intent_hash,
          expires_at: r2.authorization.expires_at,
          expires_at_derivation: "intent.timestamp(0) + ttl_seconds(60) = 60",
          canonical_signing_payload: canonicalJson(authSigningPayload(r2.authorization, policyId)),
          signature: r2.authorization.engine_signature
        }
      }
    ]
  });
}

async function extractSnapshotHash(): Promise<void> {
  const engine = makeEngine();
  const state1 = makeState();

  const snap1 = engine.exportState(state1);
  const bytes1 = encodeCanonicalState(snap1);
  const decoded1 = decodeCanonicalState(bytes1);
  const verify1 = verifySnapshot(bytes1, { expectedPolicyId: engine.computePolicyId() });
  if (verify1.status !== "ok" || !verify1.stateHash) throw new Error("verifySnapshot failed for vector 1");

  const state2 = makeState();
  state2.budget.budget_limit["agent-1"] = 999_999_999_999_999_999n;
  const snap2 = engine.exportState(state2);
  const bytes2 = encodeCanonicalState(snap2);
  const verify2 = verifySnapshot(bytes2, { expectedPolicyId: engine.computePolicyId() });
  if (verify2.status !== "ok" || !verify2.stateHash) throw new Error("verifySnapshot failed for vector 2");

  const reEncoded = encodeCanonicalState(decoded1);
  const verify3 = verifySnapshot(reEncoded, { expectedPolicyId: engine.computePolicyId() });
  if (verify3.status !== "ok" || !verify3.stateHash) throw new Error("verifySnapshot failed for vector 3");

  writeVector("snapshot-hash.json", {
    version: "1.0.0",
    vectors: [
      {
        id: "snapshot-hash-001",
        input_state: state1,
        expected: {
          snapshot_base64: b64(bytes1),
          state_hash: verify1.stateHash
        }
      },
      {
        id: "snapshot-hash-002",
        input_state: state2,
        expected: {
          snapshot_base64: b64(bytes2),
          state_hash: verify2.stateHash,
          normalized_budget_limit: "999999999999999999"
        }
      },
      {
        id: "snapshot-hash-003",
        input_snapshot_base64: b64(bytes1),
        expected: { state_hash: verify3.stateHash },
        invariant: "equals snapshot-hash-001"
      }
    ]
  });
}

async function extractAuditChain(): Promise<void> {
  const engine = makeEngine();
  const state = makeState();
  const out = engine.evaluatePure(makeIntent(200n, 1730000000), state);
  if (out.decision !== "ALLOW") throw new Error("expected ALLOW for audit-chain vectors");

  const events = engine.audit.snapshot();
  if (events.length < 3) throw new Error(`expected >=3 events, got ${events.length}`);

  const e0 = events[0];
  const e1 = events[1];
  const e2 = events[2];

  const genesis = sha256hexUtf8("OxDeAI::GENESIS::v1");
  const head1 = sha256hexUtf8(`${genesis}\n${canonicalJson(e0)}`);
  const head2 = sha256hexUtf8(`${head1}\n${canonicalJson(e1)}`);
  const head3 = sha256hexUtf8(`${head2}\n${canonicalJson(e2)}`);

  const tampered0 = { ...e0, type: "TAMPERED" };
  const tamperedHead1 = sha256hexUtf8(`${genesis}\n${canonicalJson(tampered0)}`);

  writeVector("audit-chain.json", {
    version: "1.0.0",
    hash_algorithm: "SHA256",
    separator: "0x0A",
    chain_rule: "head_(k+1) = SHA256(head_k || 0x0A || canonical(event_k))",
    vectors: [
      {
        id: "audit-chain-001",
        input: "OxDeAI::GENESIS::v1",
        expected: { genesis_hex: genesis }
      },
      {
        id: "audit-chain-002",
        input: { head_0: genesis, event_0: e0, canonical_event_0: canonicalJson(e0) },
        expected: { head_1: head1 }
      },
      {
        id: "audit-chain-003",
        input: { genesis, events: [e0, e1, e2] },
        expected: { head_1: head1, head_2: head2, head_3: head3 }
      },
      {
        id: "audit-chain-004",
        input: { original_event_0: e0, mutated_event_0: tampered0, head_0: genesis },
        expected: {
          original_head_1: head1,
          mutated_head_1: tamperedHead1,
          must_not_equal_original_head_1: true
        }
      }
    ]
  });
}

async function extractEnvelopeVerification(): Promise<void> {
  const engine = makeEngine();
  const state = makeState();

  const out = engine.evaluatePure(makeIntent(300n, 1730000000), state);
  if (out.decision !== "ALLOW") throw new Error("expected ALLOW for envelope vectors");

  const events = engine.audit.snapshot();
  const snapshotBytes = encodeCanonicalState(engine.exportState(state));
  const snapCheck = verifySnapshot(snapshotBytes, { expectedPolicyId: engine.computePolicyId() });
  if (snapCheck.status !== "ok" || !snapCheck.stateHash) throw new Error("snapshot verification failed");

  const validEnvelopeBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events
  });

  const withCheckpointEvents: EnvelopeEvent[] = [
    ...events,
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: snapCheck.stateHash,
      timestamp: makeIntent(300n, 1730000000).timestamp,
      policyId: engine.computePolicyId()
    }
  ];
  const withCheckpointBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: withCheckpointEvents
  });
  const mismatchedEvents: EnvelopeEvent[] = events.map((e) => ({
    ...e,
    policyId: "c".repeat(64)
  }));

  const mismatchedPolicyBytes = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: mismatchedEvents
  });

  const corruptBytes = new Uint8Array([1, 2, 3, 4, 5]);

  const r1 = verifyEnvelope(withCheckpointBytes, {
    expectedPolicyId: engine.computePolicyId(),
    mode: "strict"
  });
  const r2 = verifyEnvelope(validEnvelopeBytes, {
    expectedPolicyId: engine.computePolicyId(),
    mode: "best-effort"
  });
  const r3 = verifyEnvelope(mismatchedPolicyBytes, {
    expectedPolicyId: engine.computePolicyId(),
    mode: "best-effort"
  });
  const r4 = verifyEnvelope(corruptBytes, {
    expectedPolicyId: engine.computePolicyId(),
    mode: "best-effort"
  });
  const r5 = verifyEnvelope(validEnvelopeBytes, {
    expectedPolicyId: engine.computePolicyId(),
    mode: "strict"
  });

  writeVector("envelope-verification.json", {
    version: "1.0.0",
    vectors: [
      {
        id: "envelope-001",
        description: "ok — strict mode with STATE_CHECKPOINT",
        expected: {
          status: r1.status,
          policyId: r1.policyId,
          stateHash: r1.stateHash,
          auditHeadHash: r1.auditHeadHash,
          violations: r1.violations
        }
      },
      {
        id: "envelope-002",
        description: "ok — best-effort mode without checkpoint",
        expected: { status: r2.status, violations: r2.violations }
      },
      {
        id: "envelope-003",
        description: "invalid — policyId mismatch",
        expected: { status: r3.status, violations: r3.violations }
      },
      {
        id: "envelope-004",
        description: "invalid — corrupt envelope bytes",
        expected: { status: r4.status, violations: r4.violations }
      },
      {
        id: "envelope-005",
        description: "inconclusive — strict mode without checkpoint",
        expected: { status: r5.status, violations: r5.violations }
      }
    ]
  });
}

async function main(): Promise<void> {
  console.log("Extracting conformance vectors against @oxdeai/core@1.0.0");
  await extractIntentHash();
  await extractAuthorizationPayload();
  await extractSnapshotHash();
  await extractAuditChain();
  await extractEnvelopeVerification();
  console.log("done");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
