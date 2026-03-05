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

type Fingerprints = {
  policyId: string;
  stateHash: string;
  auditHeadHash: string;
};

async function runSmoke(): Promise<Fingerprints> {
  // Resolve repository root-relative dist path reliably from this file location.
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);

  // This file compiles to: packages/core/dist/test/cross_process.test.js
  // We want:              packages/core/dist/dev/smoke.js
  const smokePath = path.resolve(__dirname, "..", "dev", "smoke.js");

  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "oxdeai-smoke-"));
  const outPath = path.join(tmpDir, "determinism.json");

  const { stdout, stderr } = await execFileAsync(process.execPath, [smokePath], {
    env: {
      ...process.env,
      // Ensure deterministic environment: no colors / no locale issues.
      FORCE_COLOR: "0",
      OXDEAI_SMOKE_OUT: outPath
    },
    timeout: 30_000,
    maxBuffer: 10 * 1024 * 1024
  });

  // If smoke writes to stderr, that’s fine, but if it indicates failure, the process should exit non-zero.
  void stderr;
  void stdout;

  const parsed = JSON.parse(await readFile(outPath, "utf8")) as Fingerprints;
  return parsed;
}

test("cross-process determinism: smoke fingerprints match", async () => {
  const a = await runSmoke();
  const b = await runSmoke();

  assert.deepEqual(a, b, `fingerprints mismatch:\nA=${JSON.stringify(a)}\nB=${JSON.stringify(b)}`);
});
