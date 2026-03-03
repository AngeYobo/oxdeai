// packages/core/src/test/cross_process.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

type Fingerprints = {
  policyId: string;
  stateHash: string;
  auditHeadHash: string;
};

function parseFingerprints(stdout: string): Fingerprints {
  const get = (key: keyof Fingerprints) => {
    const re = new RegExp(`^DETERMINISM\\s+${key}=([0-9a-f]{64})$`, "m");
    const m = stdout.match(re);
    if (!m) throw new Error(`missing DETERMINISM ${key} in output:\n${stdout}`);
    return m[1];
  };

  return {
    policyId: get("policyId"),
    stateHash: get("stateHash"),
    auditHeadHash: get("auditHeadHash")
  };
}

async function runSmoke(): Promise<Fingerprints> {
  // Resolve repository root-relative dist path reliably from this file location.
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);

  // This file compiles to: packages/core/dist/test/cross_process.test.js
  // We want:              packages/core/dist/dev/smoke.js
  const smokePath = path.resolve(__dirname, "..", "dev", "smoke.js");

  const { stdout, stderr } = await execFileAsync(process.execPath, [smokePath], {
    env: {
      ...process.env,
      // Ensure deterministic environment: no colors / no locale issues.
      FORCE_COLOR: "0"
    },
    timeout: 30_000,
    maxBuffer: 10 * 1024 * 1024
  });

  // If smoke writes to stderr, that’s fine, but if it indicates failure, the process should exit non-zero.
  void stderr;

  return parseFingerprints(stdout);
}

test("cross-process determinism: smoke fingerprints match", async () => {
  const a = await runSmoke();
  const b = await runSmoke();

  assert.deepEqual(a, b, `fingerprints mismatch:\nA=${JSON.stringify(a)}\nB=${JSON.stringify(b)}`);
});