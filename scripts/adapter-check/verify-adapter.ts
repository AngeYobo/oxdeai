#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type AdapterId = "openai-tools" | "langgraph" | "openclaw";

type CheckResult = {
  name: AdapterId;
  ok: boolean;
  checks: {
    pdpSequence: boolean;
    authRequired: boolean;
    denyNoExecution: boolean;
    envelopeOk: boolean;
  };
  notes: string[];
};

const ADAPTERS: readonly AdapterId[] = ["openai-tools", "langgraph", "openclaw"] as const;
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..");

function usage(): string {
  return [
    "Usage:",
    "  verify-adapter.ts [--adapter <openai-tools|langgraph|openclaw|all>]",
    "",
    "Examples:",
    "  pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts",
    "  pnpm -C packages/conformance tsx ../../scripts/adapter-check/verify-adapter.ts --adapter langgraph"
  ].join("\n");
}

function parseAdapterArg(argv: string[]): AdapterId[] {
  let target = "all";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--adapter") {
      const v = argv[i + 1];
      if (!v) throw new Error("Missing value for --adapter");
      target = v;
      i++;
      continue;
    }
    if (a.startsWith("--adapter=")) {
      target = a.slice("--adapter=".length);
      continue;
    }
    if (a === "--help" || a === "-h") {
      console.log(usage());
      process.exit(0);
    }
    throw new Error(`Unknown argument: ${a}`);
  }

  if (target === "all") return [...ADAPTERS];
  if (target === "openai-tools" || target === "langgraph" || target === "openclaw") return [target];
  throw new Error("Invalid --adapter value (must be openai-tools|langgraph|openclaw|all)");
}

function runAdapter(adapter: AdapterId): CheckResult {
  const run = spawnSync("pnpm", ["-C", `examples/${adapter}`, "start"], {
    cwd: REPO_ROOT,
    encoding: "utf8"
  });

  const combined = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
  const lines = combined.split("\n");
  const notes: string[] = [];

  const allowedMatch = combined.match(/Allowed:\s*(\d+)/);
  const deniedMatch = combined.match(/Denied:\s*(\d+)/);
  const pdpSequence = allowedMatch?.[1] === "2" && deniedMatch?.[1] === "1";
  if (!pdpSequence) notes.push("expected summary Allowed=2 and Denied=1");

  const authRequired = combined.includes("No Authorization = no execution");
  if (!authRequired) notes.push("missing explicit authorization boundary signal");

  const denyIndex = lines.findIndex((line) => line.includes("BUDGET_EXCEEDED"));
  let denyNoExecution = denyIndex >= 0;
  if (denyNoExecution) {
    const postDenyLines = lines.slice(denyIndex);
    denyNoExecution = !postDenyLines.some((line) => line.includes("EXECUTED"));
  }
  if (!denyNoExecution) notes.push("detected execution after deny or missing deny reason");

  const envelopeOk = combined.includes("verifyEnvelope") && combined.includes("status:        ok");
  if (!envelopeOk) notes.push("missing verifyEnvelope strict success status");

  if (run.status !== 0) notes.push(`demo process exited with code ${run.status ?? "unknown"}`);

  const ok = run.status === 0 && pdpSequence && authRequired && denyNoExecution && envelopeOk;
  return {
    name: adapter,
    ok,
    checks: { pdpSequence, authRequired, denyNoExecution, envelopeOk },
    notes
  };
}

function printSummary(results: CheckResult[]): void {
  console.log("OxDeAI Adapter Verification Summary");
  console.log("==================================");

  for (const result of results) {
    console.log(`\nAdapter: ${result.name}`);
    console.log(`Status:  ${result.ok ? "PASS" : "FAIL"}`);
    console.log(`- PDP expected sequence (ALLOW/ALLOW/DENY): ${result.checks.pdpSequence ? "ok" : "fail"}`);
    console.log(`- Authorization required before execution: ${result.checks.authRequired ? "ok" : "fail"}`);
    console.log(`- DENY prevents execution: ${result.checks.denyNoExecution ? "ok" : "fail"}`);
    console.log(`- verifyEnvelope() returns ok: ${result.checks.envelopeOk ? "ok" : "fail"}`);
    if (result.notes.length > 0) {
      console.log("- Notes:");
      for (const note of result.notes) console.log(`  - ${note}`);
    }
  }
}

function main(): number {
  let adapters: AdapterId[];
  try {
    adapters = parseAdapterArg(process.argv.slice(2));
  } catch (error) {
    console.error((error as Error).message);
    console.error(usage());
    return 2;
  }

  const results = adapters.map(runAdapter);
  printSummary(results);

  return results.every((r) => r.ok) ? 0 : 1;
}

process.exit(main());
