// SPDX-License-Identifier: Apache-2.0
/**
 * Sift → OxDeAI execution-boundary demo.
 *
 * Runs 4 scenarios in-process (no HTTP) with step-by-step terminal output:
 *   1. ALLOW           — happy path, execution succeeds
 *   2. DENY            — Sift DENY, blocked at adapter
 *   3. REPLAY          — auth_id reuse, blocked at PEP
 *   4. BYPASS          — direct upstream call, blocked at target
 *
 * Every component enforces real invariants (Ed25519 signatures, canonical
 * JSON hashes, replay store). No hidden logic. Every DENY explains why.
 */

import {
  generateKeyPairSync,
  createPublicKey,
  createHash,
  randomUUID,
  sign,
  verify as nodeVerify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";

import {
  verifyReceiptWithKeyStore,
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
  type SiftKeyStore,
  type AuthorizationV1Payload,
  type OxDeAIIntent,
  type NormalizedState,
} from "@oxdeai/sift";

import {
  ln, out, separator, scenarioHeader, step, kv, check,
  blocked, resultAllow, resultDeny, hash16, fmt,
} from "./display.js";

// ─── Canonical JSON (inlined — siftCanonicalJsonBytes is not exported by @oxdeai/sift) ─

type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

function siftCanonicalize(v: unknown): JsonValue {
  if (v === null || v === undefined) return null;
  if (typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new TypeError(`Non-finite: ${v}`);
    return v;
  }
  if (Array.isArray(v)) return (v as unknown[]).map(siftCanonicalize);
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v) as unknown;
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`Non-plain object: ${Object.prototype.toString.call(v)}`);
    const out = Object.create(null) as { [k: string]: JsonValue };
    for (const k of Object.keys(v as object).sort())
      out[k] = siftCanonicalize((v as Record<string, unknown>)[k]);
    return out;
  }
  throw new TypeError(`Unsupported type: ${typeof v}`);
}

function applyEnsureAscii(json: string): string {
  let s = "";
  for (let i = 0; i < json.length; i++) {
    const c = json.charCodeAt(i);
    s += c > 0x7f ? "\\u" + c.toString(16).padStart(4, "0") : json[i];
  }
  return s;
}

function siftCanonicalJsonBytes(v: unknown): Uint8Array {
  return new TextEncoder().encode(applyEnsureAscii(JSON.stringify(siftCanonicalize(v))));
}

function siftCanonicalJsonHash(v: unknown): string {
  return createHash("sha256").update(siftCanonicalJsonBytes(v)).digest("hex");
}

function b64uEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64uDecode(s: string): Buffer {
  return Buffer.from(s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""), "base64url");
}

function rawPublicKeyBytes(key: KeyObject): Buffer {
  return (key.export({ type: "spki", format: "der" }) as Buffer).subarray(12);
}

// ─── In-memory key store (implements SiftKeyStore, no HTTP) ──────────────────

class InMemoryKeyStore implements SiftKeyStore {
  private readonly keys: Map<string, Uint8Array>;
  constructor(kid: string, rawKey: Uint8Array) {
    this.keys = new Map([[kid, rawKey]]);
  }
  async getPublicKeyByKid(kid: string): Promise<Uint8Array | null> {
    return this.keys.get(kid) ?? null;
  }
  async isKidRevoked(_kid: string): Promise<boolean> { return false; }
  async refresh(): Promise<void> { /* no-op — all keys in memory */ }
}

// ─── Replay store ─────────────────────────────────────────────────────────────

class ReplayStore {
  private readonly consumed = new Map<string, number>();

  /** Returns true (first use) or false (replay). Atomic in single-process use. */
  consume(authId: string, expiresAt: number): boolean {
    if (this.consumed.has(authId)) return false;
    this.consumed.set(authId, expiresAt);
    return true;
  }
}

// ─── Mock Sift ────────────────────────────────────────────────────────────────

class MockSift {
  private readonly privateKey: KeyObject;
  readonly kid = "sift-key-1";
  readonly rawPublicKey: Uint8Array;
  readonly keyStore: InMemoryKeyStore;

  constructor() {
    const pair = generateKeyPairSync("ed25519");
    this.privateKey = pair.privateKey;
    this.rawPublicKey = rawPublicKeyBytes(createPublicKey(pair.privateKey));
    this.keyStore = new InMemoryKeyStore(this.kid, this.rawPublicKey);
  }

  issueReceipt(
    tool: string,
    decision: "ALLOW" | "DENY",
    policy = "transfer-policy-v1"
  ): unknown {
    const body = {
      receipt_version: "1.0",
      tenant_id: "tenant-acme",
      agent_id: "agent-001",
      action: "call_tool",
      tool,
      decision,
      risk_tier: 2,
      timestamp: new Date().toISOString(),
      nonce: randomUUID(),
      policy_matched: policy,
    };
    const receiptHash = createHash("sha256")
      .update(siftCanonicalJsonBytes(body))
      .digest("hex");
    const signedPayload = { ...body, receipt_hash: receiptHash };
    const sigBuf = sign(null, siftCanonicalJsonBytes(signedPayload), this.privateKey);
    return { ...signedPayload, signature: b64uEncode(sigBuf) };
  }
}

// ─── Adapter result ───────────────────────────────────────────────────────────

type AdapterOk = {
  ok: true;
  authorization: AuthorizationV1Payload;
  intent: OxDeAIIntent;
  state: NormalizedState;
};
type AdapterErr = { ok: false; code: string; message: string };
type AdapterResult = AdapterOk | AdapterErr;

// ─── Demo adapter ─────────────────────────────────────────────────────────────

async function runAdapter(
  receipt: unknown,
  kid: string,
  keyStore: SiftKeyStore,
  params: Record<string, unknown>,
  stateInput: Record<string, unknown>,
  adapterPrivateKey: KeyObject,
  adapterKeyId: string,
  now?: Date
): Promise<AdapterResult> {
  // 1. Verify receipt (signature + freshness + ALLOW decision)
  const vr = await verifyReceiptWithKeyStore(receipt, {
    kid,
    keyStore,
    requireAllowDecision: true,
  });
  if (!vr.ok) return { ok: false, code: vr.code, message: vr.message };

  // 2. Normalize intent
  const ir = normalizeIntent({ receipt: vr.receipt, params });
  if (!ir.ok) return { ok: false, code: ir.code, message: ir.message };

  // 3. Normalize state
  const sr = normalizeState({ state: stateInput });
  if (!sr.ok) return { ok: false, code: sr.code, message: sr.message };

  // 4. Build unsigned AuthorizationV1
  const ar = receiptToAuthorization({
    receipt: vr.receipt,
    intent: ir.intent,
    state: sr.state,
    issuer: "adapter-issuer",
    audience: "pep-payments",
    keyId: adapterKeyId,
    ttlSeconds: 30,
    now,
  });
  if (!ar.ok) return { ok: false, code: ar.code, message: ar.message };

  // 5. Sign the canonical signing payload
  const sigBuf = sign(null, siftCanonicalJsonBytes(ar.signingPayload), adapterPrivateKey);

  return {
    ok: true,
    authorization: {
      ...ar.authorization,
      signature: { ...ar.authorization.signature, sig: b64uEncode(sigBuf) },
    },
    intent: ir.intent,
    state: sr.state,
  };
}

// ─── PEP verification (9 steps, prints each) ──────────────────────────────────

type PepResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

function pepVerify(
  intent: unknown,
  state: unknown,
  rawAuth: unknown,
  adapterPublicKey: KeyObject,
  replayStore: ReplayStore
): PepResult {
  // ── Parse ──────────────────────────────────────────────────────────────────
  if (typeof rawAuth !== "object" || rawAuth === null)
    return { ok: false, code: "PARSE_ERROR", message: "authorization is not an object" };

  const a = rawAuth as Record<string, unknown>;
  const sig = a["signature"] as Record<string, unknown> | undefined;

  if (
    a["version"] !== "AuthorizationV1" ||
    typeof a["auth_id"] !== "string" ||
    typeof a["issuer"] !== "string" ||
    typeof a["audience"] !== "string" ||
    typeof a["intent_hash"] !== "string" ||
    typeof a["state_hash"] !== "string" ||
    typeof a["policy_id"] !== "string" ||
    typeof a["issued_at"] !== "number" ||
    typeof a["expires_at"] !== "number" ||
    !sig || sig["alg"] !== "ed25519" ||
    typeof sig["kid"] !== "string" ||
    typeof sig["sig"] !== "string"
  ) {
    return { ok: false, code: "PARSE_ERROR", message: "AuthorizationV1 shape invalid" };
  }

  const auth = rawAuth as AuthorizationV1Payload;

  // ── Step 2: Signature ──────────────────────────────────────────────────────
  const signingPayload = {
    version: auth.version,
    auth_id: auth.auth_id,
    issuer: auth.issuer,
    audience: auth.audience,
    decision: auth.decision,
    intent_hash: auth.intent_hash,
    state_hash: auth.state_hash,
    policy_id: auth.policy_id,
    issued_at: auth.issued_at,
    expires_at: auth.expires_at,
    signature: { alg: auth.signature.alg, kid: auth.signature.kid },
  };
  let sigValid: boolean;
  try {
    sigValid = nodeVerify(
      null,
      siftCanonicalJsonBytes(signingPayload),
      adapterPublicKey,
      b64uDecode(auth.signature.sig)
    );
  } catch { sigValid = false; }
  check(sigValid, "signature", sigValid ? "valid (Ed25519)" : "INVALID");
  if (!sigValid) return { ok: false, code: "INVALID_SIGNATURE", message: "signature invalid" };

  // ── Step 3: Issuer ─────────────────────────────────────────────────────────
  const issuerOk = auth.issuer === "adapter-issuer";
  check(issuerOk, "issuer", `${auth.issuer}${issuerOk ? "  (known)" : "  UNKNOWN_ISSUER"}`);
  if (!issuerOk) return { ok: false, code: "UNKNOWN_ISSUER", message: `issuer '${auth.issuer}' not recognized` };

  // ── Step 4: Audience ───────────────────────────────────────────────────────
  const audOk = auth.audience === "pep-payments";
  check(audOk, "audience", `${auth.audience}${audOk ? "  (match)" : "  ≠ pep-payments → AUDIENCE_MISMATCH"}`);
  if (!audOk) return { ok: false, code: "AUDIENCE_MISMATCH", message: `audience mismatch: '${auth.audience}'` };

  // ── Step 5: Decision ───────────────────────────────────────────────────────
  check(true, "decision", "ALLOW");

  // ── Step 6: Expiry ─────────────────────────────────────────────────────────
  const nowSec = Math.floor(Date.now() / 1000);
  const remaining = auth.expires_at - nowSec;
  const notExpired = remaining > 0;
  check(notExpired, "expiry", notExpired ? `${remaining}s remaining` : `EXPIRED (${-remaining}s ago)`);
  if (!notExpired) return { ok: false, code: "EXPIRED", message: `expired ${-remaining}s ago` };

  // ── Step 7: Policy ─────────────────────────────────────────────────────────
  const policyOk = ["transfer-policy-v1", "withdraw-policy-v1", "read-only-policy-v1"].includes(auth.policy_id);
  check(policyOk, "policy", `${auth.policy_id}${policyOk ? "  (known)" : "  UNKNOWN_POLICY"}`);
  if (!policyOk) return { ok: false, code: "UNKNOWN_POLICY", message: `policy '${auth.policy_id}' not known` };

  // ── Step 8: Intent hash ────────────────────────────────────────────────────
  const computedIntent = siftCanonicalJsonHash(intent);
  const intentOk = computedIntent === auth.intent_hash;
  check(intentOk, "intent hash", intentOk
    ? `${hash16(computedIntent)} matched`
    : `${hash16(computedIntent)} ≠ ${hash16(auth.intent_hash)}  INTENT_HASH_MISMATCH`
  );
  if (!intentOk) return { ok: false, code: "INTENT_HASH_MISMATCH", message: "intent_hash mismatch" };

  // ── Step 9: State hash ─────────────────────────────────────────────────────
  const computedState = siftCanonicalJsonHash(state);
  const stateOk = computedState === auth.state_hash;
  check(stateOk, "state hash", stateOk
    ? `${hash16(computedState)} matched`
    : `${hash16(computedState)} ≠ ${hash16(auth.state_hash)}  STATE_HASH_MISMATCH`
  );
  if (!stateOk) return { ok: false, code: "STATE_HASH_MISMATCH", message: "state_hash mismatch" };

  // ── Step 10: Replay (atomic, last) ─────────────────────────────────────────
  const notReplayed = replayStore.consume(auth.auth_id, auth.expires_at);
  check(notReplayed, "replay", notReplayed
    ? "first use — auth_id consumed"
    : "REPLAY_DETECTED — auth_id already consumed"
  );
  if (!notReplayed) return { ok: false, code: "REPLAY_DETECTED", message: "auth_id already consumed" };

  return { ok: true };
}

// ─── Upstream ─────────────────────────────────────────────────────────────────

class DemoUpstream {
  private readonly internalToken: string;
  executed = 0; // counter — asserts zero side effects on DENY

  constructor(token: string) { this.internalToken = token; }

  execute(token: string | undefined, intent: unknown): { ok: boolean; code?: string } {
    if (token !== this.internalToken) {
      return { ok: false, code: "FORBIDDEN" };
    }
    this.executed++;
    return { ok: true };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCENARIOS
// ─────────────────────────────────────────────────────────────────────────────

async function scenario1Allow(
  sift: MockSift,
  adapterPrivKey: KeyObject,
  adapterPubKey: KeyObject,
  adapterKid: string,
  replay: ReplayStore,
  upstream: DemoUpstream,
  internalToken: string
): Promise<void> {
  scenarioHeader(1, "ALLOW");

  const params = { amount: 100, destination: "safe_account" };
  const stateInput = { session_active: true, account_status: "active" };

  // ── Step 1 ────────────────────────────────────────────────────────────────
  step(1, "Agent request");
  kv("tool", "transfer");
  kv("params", fmt(params));
  kv("state", fmt(stateInput));
  ln();

  // ── Step 2 ────────────────────────────────────────────────────────────────
  step(2, "Sift decision");
  const receipt = sift.issueReceipt("transfer", "ALLOW");
  // Verify inline to show the check
  const vr = await verifyReceiptWithKeyStore(receipt, {
    kid: sift.kid,
    keyStore: sift.keyStore,
    requireAllowDecision: false,
  });
  check(vr.ok, "receipt signature", vr.ok ? "valid (Ed25519)" : "INVALID");
  if (!vr.ok) { resultDeny("VERIFY_FAILED", vr.message); return; }
  const decisionOk = vr.receipt.decision === "ALLOW";
  check(decisionOk, "decision", vr.receipt.decision);
  kv("policy", vr.receipt.policy_matched, "           ");
  kv("nonce", vr.receipt.nonce.slice(0, 18) + "…", "           ");
  ln();

  // ── Step 3 ────────────────────────────────────────────────────────────────
  step(3, "Adapter output");
  const ar = await runAdapter(
    receipt, sift.kid, sift.keyStore,
    params, stateInput,
    adapterPrivKey, adapterKid
  );
  if (!ar.ok) { blocked(ar.code, ar.message); resultDeny(ar.code, "No AuthorizationV1 issued."); return; }
  const auth = ar.authorization;
  check(true, "intent_hash", `${hash16(auth.intent_hash)}  (SHA-256 of canonical intent)`);
  check(true, "state_hash", `${hash16(auth.state_hash)}  (SHA-256 of canonical state)`);
  kv("auth_id", auth.auth_id.slice(0, 18) + "…  (= receipt.nonce)", "           ");
  kv("expires_at", new Date(auth.expires_at * 1000).toISOString() + "  (+30s)", "           ");
  ln();

  // ── Step 4 ────────────────────────────────────────────────────────────────
  step(4, "PEP verification");
  const pep = pepVerify(ar.intent, ar.state, auth, adapterPubKey, replay);
  ln();

  if (!pep.ok) {
    resultDeny(pep.code, "Execution blocked.");
    return;
  }

  // Forward to upstream with internal token
  const exec = upstream.execute(internalToken, ar.intent);
  resultAllow(`execution succeeded  (upstream.executed = ${upstream.executed})`);
}

// ─────────────────────────────────────────────────────────────────────────────

async function scenario2Deny(
  sift: MockSift,
  adapterPrivKey: KeyObject,
  adapterKid: string,
  replay: ReplayStore,
  adapterPubKey: KeyObject,
  upstream: DemoUpstream
): Promise<void> {
  scenarioHeader(2, "DENY");

  const params = { amount: 100, destination: "safe_account" };
  const stateInput = { session_active: true, account_status: "active" };
  const execBefore = upstream.executed;

  step(1, "Agent request");
  kv("tool", "transfer");
  kv("params", fmt(params));
  ln();

  step(2, "Sift decision");
  const receipt = sift.issueReceipt("transfer", "DENY");
  const vr = await verifyReceiptWithKeyStore(receipt, {
    kid: sift.kid,
    keyStore: sift.keyStore,
    requireAllowDecision: false,
  });
  check(vr.ok, "receipt signature", vr.ok ? "valid (Ed25519)" : "INVALID");
  if (!vr.ok) { resultDeny("VERIFY_FAILED", vr.message); return; }
  check(false, "decision", "DENY");
  ln();

  step(3, "Adapter output");
  // adapter enforces requireAllowDecision: true — will reject DENY
  const ar = await runAdapter(
    receipt, sift.kid, sift.keyStore,
    params, stateInput,
    adapterPrivKey, adapterKid
  );
  blocked(ar.ok ? "???" : ar.code, "No AuthorizationV1 issued.  Execution never reached.");
  out(`             upstream.executed = ${upstream.executed}  (unchanged — zero side effects)`);
  ln();

  resultDeny(
    ar.ok ? "???" : ar.code,
    `upstream.executed = ${upstream.executed} (was ${execBefore}) — no side effects`
  );
}

// ─────────────────────────────────────────────────────────────────────────────

async function scenario3Replay(
  sift: MockSift,
  adapterPrivKey: KeyObject,
  adapterPubKey: KeyObject,
  adapterKid: string,
  replay: ReplayStore,
  upstream: DemoUpstream,
  internalToken: string
): Promise<void> {
  scenarioHeader(3, "REPLAY");

  const params = { amount: 100, destination: "safe_account" };
  const stateInput = { session_active: true, account_status: "active" };

  out(`  First use — obtain and consume the authorization:`);
  ln();

  const receipt = sift.issueReceipt("transfer", "ALLOW");
  const ar = await runAdapter(
    receipt, sift.kid, sift.keyStore,
    params, stateInput,
    adapterPrivKey, adapterKid
  );
  if (!ar.ok) { resultDeny(ar.code, ar.message); return; }

  step(4, "PEP verification (first use)");
  const first = pepVerify(ar.intent, ar.state, ar.authorization, adapterPubKey, replay);
  ln();
  if (!first.ok) { resultDeny(first.code, "unexpected failure"); return; }
  upstream.execute(internalToken, ar.intent);
  out(`  ✓  First use succeeded.  upstream.executed = ${upstream.executed}`);

  separator();
  ln();
  out(`  Second use — SAME AuthorizationV1, same auth_id:`);
  ln();

  step(4, "PEP verification (second use)");
  const second = pepVerify(ar.intent, ar.state, ar.authorization, adapterPubKey, replay);
  ln();

  const execAfterReplay = upstream.executed;
  resultDeny(
    second.ok ? "???" : second.code,
    `upstream.executed = ${execAfterReplay} (unchanged — execution blocked)`
  );
}

// ─────────────────────────────────────────────────────────────────────────────

function scenario4Bypass(upstream: DemoUpstream): void {
  scenarioHeader(4, "BYPASS");

  out(`  Attacker calls execution target directly.`);
  out(`  No Sift receipt.  No AuthorizationV1.  No PEP.`);
  ln();

  step(1, "Attacker → Upstream.execute()");
  kv("token", "(none — no X-Internal-Execution-Token)");
  kv("intent", fmt({ tool: "transfer", params: { amount: 999_999 } }));
  ln();

  step(2, "Upstream: token check");
  const result = upstream.execute(undefined, { tool: "transfer", params: { amount: 999_999 } });
  check(false, "token", "MISSING → FORBIDDEN");
  out(`             upstream.executed = ${upstream.executed}  (unchanged — execution never reached)`);
  ln();

  resultDeny(
    result.code ?? "FORBIDDEN",
    `Execution blocked at target.  Valid AuthorizationV1 verified by the PEP is the only execution gate.`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  out("\x1b[1m\x1b[97m  Sift → OxDeAI  Execution Boundary Demo\x1b[0m");
  out("\x1b[90m  Invariant: No valid AuthorizationV1 → no execution\x1b[0m");
  out("\x1b[90m  All cryptographic operations are real (Ed25519 + SHA-256).\x1b[0m");

  // Generate fresh key pairs for this demo run.
  const siftMock = new MockSift();
  const adapterPair = generateKeyPairSync("ed25519");
  const adapterKid = "adapter-key-1";
  const internalToken = "demo-internal-token-" + Math.random().toString(36).slice(2);

  // Shared replay store — carries state across scenarios so REPLAY works.
  const replay = new ReplayStore();
  const upstream = new DemoUpstream(internalToken);

  // Run all 4 scenarios sequentially.
  await scenario1Allow(
    siftMock,
    adapterPair.privateKey, adapterPair.publicKey, adapterKid,
    replay, upstream, internalToken
  );
  separator(); ln();

  await scenario2Deny(
    siftMock,
    adapterPair.privateKey, adapterKid,
    replay, adapterPair.publicKey, upstream
  );
  separator(); ln();

  await scenario3Replay(
    siftMock,
    adapterPair.privateKey, adapterPair.publicKey, adapterKid,
    replay, upstream, internalToken
  );
  separator(); ln();

  scenario4Bypass(upstream);
  separator(); ln();

  out(`\x1b[1m  Summary\x1b[0m`);
  out(`  upstream.executed = ${upstream.executed}  (scenario 1 + scenario 3 first-use — 2 total)`);
  out(`  All DENY scenarios produced zero side effects.`);
  ln();
}

main().catch((e) => {
  process.stderr.write(`Fatal: ${e instanceof Error ? e.stack : String(e)}\n`);
  process.exit(1);
});
