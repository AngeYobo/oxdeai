import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";

import {
  PolicyEngine,
  encodeCanonicalState,
  encodeEnvelope,
  verifyAuditEvents,
  verifyAuthorization,
  verifyEnvelope,
  verifySnapshot
} from "@oxdeai/core";
import type { ActionType, AuthorizationV1, Intent, KeySet, State, VerificationResult } from "@oxdeai/core";

import { appendAuditEvents, normalizeStateBigInts, readAuditEvents, readStateFile, resetAuditFile, writeStateFile } from "./store.js";

type Flags = {
  json?: boolean;
  state?: string;
  audit?: string;
  file?: string;
  out?: string;
  agent?: string;
  nonce?: string;
  asset?: string;
  kind?: "snapshot" | "audit" | "envelope" | "authorization";
  mode?: "strict" | "best-effort";
  expectedPolicyId?: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  consumedAuthId?: string;
  trustedKeyset?: string;
  requireSignatureVerification?: boolean;
  legacyHmacSecret?: string;
};

type Io = {
  out: (line: string) => void;
  err: (line: string) => void;
  now: () => number;
};

const DEFAULT_STATE_PATH = ".oxdeai/state.json";
const DEFAULT_AUDIT_PATH = ".oxdeai/audit.ndjson";
const ACTION_TYPES = new Set<ActionType>(["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"]);
const EXIT_CODE_OK = 0;
const EXIT_CODE_INVALID = 1;
const EXIT_CODE_USAGE = 2;
const EXIT_CODE_INCONCLUSIVE = 3;

function usage(): string {
  return `oxdeai CLI

Usage:
  oxdeai build [--state <state.json>] [--out <snapshot.bin>] [--json]
  oxdeai verify --kind <snapshot|audit|envelope|authorization> [--file <path>|-] [--mode <strict|best-effort>] [--expected-policy-id <hex>] [--expected-issuer <id>] [--expected-audience <id>] [--consumed-auth-id <id>] [--trusted-keyset <keyset.json>] [--require-signature] [--legacy-hmac-secret <secret>] [--json]
  oxdeai replay [--json]
  oxdeai init --file <policy.json> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai launch <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai make-envelope --out <file> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai verify-envelope <file> [--json]
  oxdeai verify-audit [--audit <audit.ndjson>] [--json]
  oxdeai snapshot-hash [--state <state.json>] [--json]
  oxdeai audit [--audit <audit.ndjson>] [--json]
  oxdeai state [--state <state.json>] [--json]`;
}

function parseFlags(argv: string[]): { args: string[]; flags: Flags } {
  const args: string[] = [];
  const flags: Flags = {};

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") continue;
    if (!a.startsWith("--")) {
      args.push(a);
      continue;
    }

    if (a === "--json") {
      flags.json = true;
      continue;
    }

    const next = () => {
      const v = argv[++i];
      if (!v) throw new Error(`Missing value for ${a}`);
      return v;
    };

    if (a === "--state") {
      flags.state = next();
      continue;
    }
    if (a === "--audit") {
      flags.audit = next();
      continue;
    }
    if (a === "--file") {
      flags.file = next();
      continue;
    }
    if (a === "--out") {
      flags.out = next();
      continue;
    }
    if (a === "--agent") {
      flags.agent = next();
      continue;
    }
    if (a === "--nonce") {
      flags.nonce = next();
      continue;
    }
    if (a === "--asset") {
      flags.asset = next();
      continue;
    }
    if (a === "--kind") {
      const v = next();
      if (v !== "snapshot" && v !== "audit" && v !== "envelope" && v !== "authorization") {
        throw new Error("Invalid --kind value (must be snapshot|audit|envelope|authorization)");
      }
      flags.kind = v;
      continue;
    }
    if (a === "--mode") {
      const v = next();
      if (v !== "strict" && v !== "best-effort") {
        throw new Error("Invalid --mode value (must be strict|best-effort)");
      }
      flags.mode = v;
      continue;
    }
    if (a === "--expected-policy-id") {
      flags.expectedPolicyId = next();
      continue;
    }
    if (a === "--expected-issuer") {
      flags.expectedIssuer = next();
      continue;
    }
    if (a === "--expected-audience") {
      flags.expectedAudience = next();
      continue;
    }
    if (a === "--consumed-auth-id") {
      flags.consumedAuthId = next();
      continue;
    }
    if (a === "--trusted-keyset") {
      flags.trustedKeyset = next();
      continue;
    }
    if (a === "--require-signature") {
      flags.requireSignatureVerification = true;
      continue;
    }
    if (a === "--legacy-hmac-secret") {
      flags.legacyHmacSecret = next();
      continue;
    }

    if (a.startsWith("--state=")) {
      flags.state = a.slice(8);
      continue;
    }
    if (a.startsWith("--audit=")) {
      flags.audit = a.slice(8);
      continue;
    }
    if (a.startsWith("--file=")) {
      flags.file = a.slice(7);
      continue;
    }
    if (a.startsWith("--out=")) {
      flags.out = a.slice(6);
      continue;
    }
    if (a.startsWith("--agent=")) {
      flags.agent = a.slice(8);
      continue;
    }
    if (a.startsWith("--nonce=")) {
      flags.nonce = a.slice(8);
      continue;
    }
    if (a.startsWith("--asset=")) {
      flags.asset = a.slice(8);
      continue;
    }
    if (a.startsWith("--kind=")) {
      const v = a.slice(7);
      if (v !== "snapshot" && v !== "audit" && v !== "envelope" && v !== "authorization") {
        throw new Error("Invalid --kind value (must be snapshot|audit|envelope|authorization)");
      }
      flags.kind = v;
      continue;
    }
    if (a.startsWith("--mode=")) {
      const v = a.slice(7);
      if (v !== "strict" && v !== "best-effort") {
        throw new Error("Invalid --mode value (must be strict|best-effort)");
      }
      flags.mode = v;
      continue;
    }
    if (a.startsWith("--expected-policy-id=")) {
      flags.expectedPolicyId = a.slice("--expected-policy-id=".length);
      continue;
    }
    if (a.startsWith("--expected-issuer=")) {
      flags.expectedIssuer = a.slice("--expected-issuer=".length);
      continue;
    }
    if (a.startsWith("--expected-audience=")) {
      flags.expectedAudience = a.slice("--expected-audience=".length);
      continue;
    }
    if (a.startsWith("--consumed-auth-id=")) {
      flags.consumedAuthId = a.slice("--consumed-auth-id=".length);
      continue;
    }
    if (a.startsWith("--trusted-keyset=")) {
      flags.trustedKeyset = a.slice("--trusted-keyset=".length);
      continue;
    }
    if (a.startsWith("--legacy-hmac-secret=")) {
      flags.legacyHmacSecret = a.slice("--legacy-hmac-secret=".length);
      continue;
    }

    throw new Error(`Unknown flag: ${a}`);
  }

  return { args, flags };
}

function toJson(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `${v.toString()}n` : v), 2);
}

function parseBigIntArg(input: string): bigint {
  const s = input.endsWith("n") ? input.slice(0, -1) : input;
  return BigInt(s);
}

async function readStdinBytes(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Uint8Array.from(Buffer.concat(chunks));
}

function parseAuditInputBytes(bytes: Uint8Array): unknown[] {
  const text = new TextDecoder().decode(bytes).trim();
  if (text.length === 0) return [];
  if (text.startsWith("[")) {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new Error("audit payload must be a JSON array or NDJSON");
    return parsed;
  }
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function parseJsonObjectBytes<T>(bytes: Uint8Array, label: string): T {
  const text = new TextDecoder().decode(bytes).trim();
  if (text.length === 0) throw new Error(`${label} payload is empty`);
  const parsed = JSON.parse(text) as unknown;
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} payload must be a JSON object`);
  }
  return parsed as T;
}

function verificationExitCode(result: VerificationResult): number {
  if (result.status === "ok") return EXIT_CODE_OK;
  if (result.status === "inconclusive") return EXIT_CODE_INCONCLUSIVE;
  return EXIT_CODE_INVALID;
}

function writePayload(out: (line: string) => void, flags: Flags, payload: unknown, humanSummary?: string): void {
  if (flags.json) {
    out(toJson(payload));
    return;
  }
  if (humanSummary) {
    out(humanSummary);
    return;
  }
  out(toJson(payload));
}

function verificationSummary(kind: Flags["kind"], result: VerificationResult): string {
  const label = kind ?? "artifact";
  const lines = [`${label}: ${result.status.toUpperCase()}`];
  if (result.policyId) lines.push(`policyId: ${result.policyId}`);
  if (result.stateHash) lines.push(`stateHash: ${result.stateHash}`);
  if (result.auditHeadHash) lines.push(`auditHeadHash: ${result.auditHeadHash}`);
  if (result.violations.length === 0) {
    lines.push("violations: none");
  } else {
    lines.push(`violations: ${result.violations.map((v) => v.code).join(", ")}`);
  }
  return lines.join("\n");
}

async function readTrustedKeySet(path: string | undefined): Promise<KeySet[] | undefined> {
  if (!path) return undefined;
  const text = await readFile(path, "utf8");
  const parsed = JSON.parse(text) as unknown;
  if (Array.isArray(parsed)) return parsed as KeySet[];
  if (parsed && typeof parsed === "object") return [parsed as KeySet];
  throw new Error("trusted keyset payload must be a JSON object or array");
}

function buildValidationIntent(state: State): Intent {
  const agent = Object.keys(state.budget.budget_limit)[0] ?? "agent";
  const action_type = state.allowlists.action_types?.[0] ?? "PAYMENT";
  const target = state.allowlists.targets?.[0] ?? "target:probe";
  return {
    intent_id: "validate-intent",
    type: "EXECUTE",
    agent_id: agent,
    action_type,
    amount: 0n,
    asset: state.allowlists.assets?.[0],
    target,
    timestamp: 0,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 0n,
    signature: "validate-signature"
  };
}

function validateStateStructure(state: State): void {
  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "validate-secret",
    authorization_ttl_seconds: 1
  });
  const probe = buildValidationIntent(state);
  const out = engine.evaluatePure(probe, structuredClone(state), { mode: "fail-fast" });
  if (out.decision === "DENY" && out.reasons.includes("STATE_INVALID")) {
    throw new Error("STATE_INVALID");
  }
}

function buildEngine(state: State): PolicyEngine {
  const secret = process.env["OXDEAI_ENGINE_SECRET"] ?? "dev-secret";
  const ttl = Number(process.env["OXDEAI_AUTH_TTL_SECONDS"] ?? "120");
  return new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: secret,
    authorization_ttl_seconds: Number.isFinite(ttl) ? ttl : 120
  });
}

export async function runCli(argv: string[], io?: Partial<Io>): Promise<number> {
  const out = io?.out ?? ((line: string) => console.log(line));
  const err = io?.err ?? ((line: string) => console.error(line));
  const now = io?.now ?? (() => Math.floor(Date.now() / 1000));

  let parsed: { args: string[]; flags: Flags };
  try {
    parsed = parseFlags(argv);
  } catch (e) {
    err((e as Error).message);
    err(usage());
    return EXIT_CODE_USAGE;
  }

  const { args, flags } = parsed;
  const cmd = args[0];
  if (!cmd) {
    err(usage());
    return EXIT_CODE_USAGE;
  }

  const statePath = flags.state ?? DEFAULT_STATE_PATH;
  const auditPath = flags.audit ?? DEFAULT_AUDIT_PATH;

  try {
    if (cmd === "build") {
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const snapshot = engine.exportState(state);
      const snapshotBytes = encodeCanonicalState(snapshot);
      const verified = verifySnapshot(snapshotBytes, flags.expectedPolicyId ? { expectedPolicyId: flags.expectedPolicyId } : undefined);

      if (flags.out) {
        await mkdir(dirname(flags.out), { recursive: true });
        await writeFile(flags.out, Buffer.from(snapshotBytes));
      }

      const payload = {
        ok: verified.ok,
        status: verified.status,
        policyId: snapshot.policyId,
        stateHash: verified.stateHash,
        violations: verified.violations,
        snapshotBytes: snapshotBytes.length,
        out: flags.out
      };
      writePayload(out, flags, payload, `build: ${verified.status.toUpperCase()}\npolicyId: ${snapshot.policyId}\nstateHash: ${verified.stateHash ?? "unknown"}${flags.out ? `\nout: ${flags.out}` : ""}`);
      return verificationExitCode(verified);
    }

    if (cmd === "verify") {
      if (!flags.kind) throw new Error("Usage: verify --kind <snapshot|audit|envelope|authorization> [--file <path>|-]");
      const mode = flags.mode ?? "strict";
      const fromFile = flags.file && flags.file !== "-";
      const bytes = fromFile
        ? Uint8Array.from(await readFile(flags.file as string))
        : await readStdinBytes();

      if (flags.kind === "snapshot") {
        const res = verifySnapshot(bytes, flags.expectedPolicyId ? { expectedPolicyId: flags.expectedPolicyId } : undefined);
        writePayload(out, flags, res, verificationSummary(flags.kind, res));
        return verificationExitCode(res);
      }

      if (flags.kind === "envelope") {
        const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
        const res = verifyEnvelope(bytes, {
          mode,
          expectedPolicyId: flags.expectedPolicyId,
          expectedIssuer: flags.expectedIssuer,
          trustedKeySets,
          requireSignatureVerification: flags.requireSignatureVerification
        });
        writePayload(out, flags, res, verificationSummary(flags.kind, res));
        return verificationExitCode(res);
      }

      if (flags.kind === "authorization") {
        const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
        const auth = parseJsonObjectBytes<AuthorizationV1>(bytes, "authorization");
        const res = verifyAuthorization(auth, {
          now: now(),
          expectedIssuer: flags.expectedIssuer,
          expectedAudience: flags.expectedAudience,
          expectedPolicyId: flags.expectedPolicyId,
          consumedAuthIds: flags.consumedAuthId ? [flags.consumedAuthId] : [],
          trustedKeySets,
          requireSignatureVerification: flags.requireSignatureVerification,
          legacyHmacSecret: flags.legacyHmacSecret
        });
        writePayload(out, flags, res, verificationSummary(flags.kind, res));
        return verificationExitCode(res);
      }

      const events = parseAuditInputBytes(bytes);
      const res = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], {
        mode,
        expectedPolicyId: flags.expectedPolicyId
      });
      writePayload(out, flags, res, verificationSummary(flags.kind, res));
      return verificationExitCode(res);
    }

    if (cmd === "replay") {
      const payload = {
        ok: false,
        status: "unsupported",
        message: "Replay verifier is a protocol-aware stub in @oxdeai/cli v0.1.x. Use verify --kind audit for deterministic offline chain checks."
      };
      writePayload(out, flags, payload, `${payload.status.toUpperCase()}: ${payload.message}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "init") {
      if (!flags.file) throw new Error("Missing --file <policy.json>");
      const text = await readFile(flags.file, "utf8");
      const state = normalizeStateBigInts(JSON.parse(text));
      validateStateStructure(state);
      await writeStateFile(statePath, state);
      await resetAuditFile(auditPath);
      writePayload(out, flags, { ok: true }, "OK");
      return EXIT_CODE_OK;
    }

    if (cmd === "state") {
      const state = await readStateFile(statePath);
      writePayload(out, flags, state);
      return EXIT_CODE_OK;
    }

    if (cmd === "audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "best-effort" });
      const payload = {
        headHash: verified.auditHeadHash && verified.auditHeadHash.length > 0 ? verified.auditHeadHash : "GENESIS",
        verify: verified.ok,
        events
      };
      writePayload(out, flags, payload);
      return EXIT_CODE_OK;
    }

    if (cmd === "verify-audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "strict" });
      writePayload(out, flags, verified, verificationSummary("audit", verified));
      return verificationExitCode(verified);
    }

    if (cmd === "verify-envelope") {
      const file = args[1] ?? flags.file;
      if (!file) throw new Error("Usage: verify-envelope <file>");
      const bytes = Uint8Array.from(await readFile(file));
      const verified = verifyEnvelope(bytes, { mode: "strict" });
      writePayload(out, flags, verified, verificationSummary("envelope", verified));
      return verificationExitCode(verified);
    }

    if (cmd === "make-envelope") {
      if (!flags.out) throw new Error("Usage: make-envelope --out <file>");
      const state = await readStateFile(statePath);
      const events = await readAuditEvents(auditPath);
      const engine = buildEngine(state);
      const snapshotBytes = encodeCanonicalState(engine.exportState(state));
      const envelope = encodeEnvelope({
        formatVersion: 1,
        snapshot: snapshotBytes,
        events: events as Parameters<typeof encodeEnvelope>[0]["events"]
      });

      await mkdir(dirname(flags.out), { recursive: true });
      await writeFile(flags.out, Buffer.from(envelope));
      const payload = { ok: true, file: flags.out };
      writePayload(out, flags, payload, `OK: ${flags.out}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "snapshot-hash") {
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const snapshot = engine.exportState(state);
      const bytes = encodeCanonicalState(snapshot);
      const verified = verifySnapshot(bytes);
      const payload = {
        policyId: snapshot.policyId,
        stateHash: verified.stateHash,
        status: verified.status,
        violations: verified.violations
      };
      writePayload(out, flags, payload, `snapshot: ${verified.status.toUpperCase()}\npolicyId: ${snapshot.policyId}\nstateHash: ${verified.stateHash ?? "unknown"}`);
      return verificationExitCode(verified);
    }

    if (cmd === "launch") {
      const action = args[1] as ActionType | undefined;
      const amountRaw = args[2];
      const target = args[3];
      if (!action || !amountRaw || !target) throw new Error("Usage: launch <actionType> <amount> <target> --agent <id> --nonce <n>");
      if (!ACTION_TYPES.has(action)) throw new Error(`Invalid actionType: ${action}`);
      if (!flags.agent) throw new Error("Missing --agent <id>");
      if (!flags.nonce) throw new Error("Missing --nonce <n>");

      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const ts = now();

      const intent: Intent = {
        intent_id: `intent:${flags.agent}:${flags.nonce}`,
        type: "EXECUTE",
        agent_id: flags.agent,
        action_type: action,
        amount: parseBigIntArg(amountRaw),
        asset: flags.asset,
        target,
        timestamp: ts,
        metadata_hash: "0x" + "0".repeat(64),
        nonce: parseBigIntArg(flags.nonce),
        signature: "cli-signature-placeholder"
      };

      const outEval = engine.evaluatePure(intent, state, { mode: "fail-fast" });
      const emitted = engine.audit.snapshot();
      await appendAuditEvents(auditPath, emitted);

      if (outEval.decision === "ALLOW") {
        await writeStateFile(statePath, outEval.nextState);
        const payload = { decision: "ALLOW" as const, authorization_id: outEval.authorization.authorization_id, reasons: [] as string[] };
        writePayload(out, flags, payload, `ALLOW: ${payload.authorization_id}`);
        return EXIT_CODE_OK;
      }

      const payload = { decision: "DENY" as const, reasons: outEval.reasons };
      writePayload(out, flags, payload, `DENY: ${toJson(payload.reasons)}`);
      return EXIT_CODE_OK;
    }

    err(usage());
    return EXIT_CODE_USAGE;
  } catch (e) {
    err((e as Error).message);
    return EXIT_CODE_INVALID;
  }
}

async function main(): Promise<void> {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main();
}
