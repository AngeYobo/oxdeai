#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import crypto from "node:crypto";

const [artifactPath] = process.argv.slice(2);
if (!artifactPath) {
  console.error("Usage: node scripts/verify-security-gate-artifact.mjs <artifact.json>");
  process.exit(2);
}

const stableStringify = (value) => {
  const sorter = (v) => {
    if (Array.isArray(v)) return v.map(sorter);
    if (v && typeof v === "object") {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = sorter(v[k]);
          return acc;
        }, {});
    }
    return v;
  };
  return JSON.stringify(sorter(value));
};

const sha256 = (v) => crypto.createHash("sha256").update(stableStringify(v)).digest("hex");

const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
const { artifactHash, ...rest } = artifact;
const computed = sha256(rest);

const ok = artifactHash && artifactHash === computed;
console.log(`Decision: ${artifact.decision ?? "unknown"}`);
console.log(`Computed hash: ${computed}`);
console.log(`Artifact hash:  ${artifactHash ?? "(missing)"}`);
console.log(`Result: ${ok ? "PASS" : "FAIL"}`);
process.exit(ok ? 0 : 1);
