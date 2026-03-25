// packages/core/src/test/cross_process.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { promisify } from "node:util";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

// This file compiles to: packages/core/dist/test/cross_process.test.js
// Sibling scripts live at: packages/core/dist/dev/<name>.js
function devScript(name: string): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  return path.resolve(__dirname, "..", "dev", name);
}

// ── I5: smoke fingerprint determinism ────────────────────────────────────

type Fingerprints = {
  policyId: string;
  stateHash: string;
  auditHeadHash: string;
};

async function runSmoke(): Promise<Fingerprints> {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "oxdeai-smoke-"));
  const outPath = path.join(tmpDir, "determinism.json");

  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [devScript("smoke.js")],
    {
      env: { ...process.env, FORCE_COLOR: "0", OXDEAI_SMOKE_OUT: outPath },
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024
    }
  );
  void stderr;
  void stdout;

  return JSON.parse(await readFile(outPath, "utf8")) as Fingerprints;
}

test("cross-process determinism: smoke fingerprints match", async () => {
  const a = await runSmoke();
  const b = await runSmoke();
  assert.deepEqual(a, b, `fingerprints mismatch:\nA=${JSON.stringify(a)}\nB=${JSON.stringify(b)}`);
});

// ── D-5: cross-process decision determinism ───────────────────────────────

type DecisionOutput = {
  decisions: string[];
  authIds: (string | null)[];
  finalStateHash: string;
  policyId: string;
  auditHeadHash: string;
};

async function runDecisionSubprocess(): Promise<DecisionOutput> {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "oxdeai-decision-"));
  const outPath = path.join(tmpDir, "decision.json");

  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [devScript("decision-subprocess.js")],
    {
      env: { ...process.env, FORCE_COLOR: "0", OXDEAI_DECISION_OUT: outPath },
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024
    }
  );
  void stderr;
  void stdout;

  return JSON.parse(await readFile(outPath, "utf8")) as DecisionOutput;
}

test("D-5 cross-process decision determinism: all outputs match", async () => {
  const a = await runDecisionSubprocess();
  const b = await runDecisionSubprocess();

  assert.deepEqual(
    a.decisions,
    b.decisions,
    `decision sequence mismatch:\nA=${JSON.stringify(a.decisions)}\nB=${JSON.stringify(b.decisions)}`
  );
  assert.deepEqual(
    a.authIds,
    b.authIds,
    `authId sequence mismatch:\nA=${JSON.stringify(a.authIds)}\nB=${JSON.stringify(b.authIds)}`
  );
  assert.equal(
    a.finalStateHash,
    b.finalStateHash,
    `finalStateHash mismatch:\nA=${a.finalStateHash}\nB=${b.finalStateHash}`
  );
  assert.equal(
    a.policyId,
    b.policyId,
    `policyId mismatch:\nA=${a.policyId}\nB=${b.policyId}`
  );
  assert.equal(
    a.auditHeadHash,
    b.auditHeadHash,
    `auditHeadHash mismatch:\nA=${a.auditHeadHash}\nB=${b.auditHeadHash}`
  );
});
