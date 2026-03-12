#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(__filename), "..");

const ADAPTERS = [
  "openai-tools",
  "langgraph",
  "crewai",
  "openai-agents-sdk",
  "autogen",
  "openclaw",
];

function parseArgs(argv) {
  let one = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--one") {
      one = argv[i + 1] ?? null;
      i += 1;
    }
  }
  return { one };
}

function runChecked(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });

  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
    throw new Error(`${command} ${args.join(" ")} failed in ${cwd}\n${output}`);
  }

  return [result.stdout, result.stderr].filter(Boolean).join("\n");
}

async function captureDemoOutput(adapterDir) {
  const runUrl = pathToFileURL(path.join(adapterDir, "dist", "run.js")).href;
  const runModule = await import(runUrl);
  if (typeof runModule.runDemo !== "function") {
    throw new Error(`${path.basename(adapterDir)}: dist/run.js does not export runDemo`);
  }

  const lines = [];
  await runModule.runDemo((msg) => {
    lines.push(String(msg));
  });
  return lines.join("\n");
}

function countMatches(text, pattern) {
  return [...text.matchAll(pattern)].length;
}

function assertOutput(adapter, output) {
  const required = [
    "decision 1: ALLOW",
    "decision 2: ALLOW",
    "decision 3: DENY",
    "verifyEnvelope() => ok",
    "└─ DENY  reasons: BUDGET_EXCEEDED",
  ];

  for (const needle of required) {
    if (!output.includes(needle)) {
      throw new Error(`${adapter}: missing required output: ${needle}`);
    }
  }

  const executedCount = countMatches(output, /└─ EXECUTED/g);
  if (executedCount !== 2) {
    throw new Error(`${adapter}: expected exactly 2 executed actions, got ${executedCount}`);
  }
}

async function assertMissingAuthorizationIsRejected(adapterDir, adapter) {
  const pepUrl = pathToFileURL(path.join(adapterDir, "dist", "pep.js")).href;
  const policyUrl = pathToFileURL(path.join(adapterDir, "dist", "policy.js")).href;

  const pepModule = await import(pepUrl);
  const policyModule = await import(policyUrl);

  const { guardedProvision } = pepModule;
  const { engine, makeState } = policyModule;

  if (typeof guardedProvision !== "function") {
    throw new Error(`${adapter}: dist/pep.js does not export guardedProvision`);
  }
  if (!engine || typeof engine.evaluatePure !== "function") {
    throw new Error(`${adapter}: dist/policy.js does not expose engine.evaluatePure`);
  }
  if (typeof makeState !== "function") {
    throw new Error(`${adapter}: dist/policy.js does not export makeState`);
  }

  const originalEvaluatePure = engine.evaluatePure.bind(engine);
  engine.evaluatePure = () => ({
    decision: "ALLOW",
    nextState: makeState(),
  });

  let threw = false;
  try {
    guardedProvision("a100", "us-east-1", makeState(), 1_733_338_614, () => {});
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("ALLOW with no Authorization")) {
      throw new Error(`${adapter}: unexpected missing-authorization failure: ${message}`);
    }
    threw = true;
  } finally {
    engine.evaluatePure = originalEvaluatePure;
  }

  if (!threw) {
    throw new Error(`${adapter}: missing authorization did not fail closed`);
  }
}

async function validateAdapter(adapter) {
  const adapterDir = path.join(repoRoot, "examples", adapter);
  const runFile = path.join(adapterDir, "dist", "run.js");

  if (!existsSync(adapterDir)) {
    throw new Error(`Unknown adapter example: ${adapter}`);
  }

  runChecked("pnpm", ["-C", adapterDir, "build"], repoRoot);

  if (!existsSync(runFile)) {
    throw new Error(`${adapter}: missing built entrypoint ${runFile}`);
  }

  const output = await captureDemoOutput(adapterDir);
  assertOutput(adapter, output);
  await assertMissingAuthorizationIsRejected(adapterDir, adapter);

  return {
    adapter,
    executed: 2,
    denied: 1,
  };
}

async function main() {
  const { one } = parseArgs(process.argv.slice(2));
  const adapters = one ? [one] : ADAPTERS;
  const results = [];

  for (const adapter of adapters) {
    const result = await validateAdapter(adapter);
    results.push(result);
    console.log(`${adapter.padEnd(20, ".")} PASS`);
  }

  if (results.length > 1) {
    console.log("\nAdapter validation summary");
    for (const result of results) {
      console.log(
        `${result.adapter.padEnd(20, ".")} PASS  decisions=ALLOW,ALLOW,DENY  verifyEnvelope=ok`
      );
    }
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
