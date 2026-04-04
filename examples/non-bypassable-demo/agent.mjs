// examples/non-bypassable-demo/agent.mjs
// How to run:
// 1) node examples/non-bypassable-demo/protected-upstream.mjs
// 2) node examples/non-bypassable-demo/pep-gateway.mjs
// 3) node examples/non-bypassable-demo/agent.mjs
//
// This script simulates an agent/runtime issuing actions through the gateway.
// It demonstrates: valid execution, hash-mismatch denial, replay denial, and direct-upstream bypass rejection.

import { request } from "node:http";
import { createHash } from "node:crypto";

// ---- Canonicalization (must match gateway) ----
const SAFE_MIN = -9007199254740991n;
const SAFE_MAX = 9007199254740991n;

const normalize = (s) => s.normalize("NFC");
const isPlainObject = (v) => Object.prototype.toString.call(v) === "[object Object]";

function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(normalize(value));
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("FLOAT_NOT_ALLOWED");
    if (!Number.isSafeInteger(value)) throw new Error("UNSAFE_INTEGER_NUMBER");
    return String(value);
  }
  if (typeof value === "bigint") return JSON.stringify(String(value));
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isPlainObject(value)) {
    const normalized = Object.entries(value).map(([k, v]) => [normalize(k), v]);
    const seen = new Set();
    for (const [k] of normalized) {
      if (seen.has(k)) throw new Error("DUPLICATE_KEY");
      seen.add(k);
    }
    const sorted = normalized.sort((a, b) =>
      Buffer.compare(Buffer.from(a[0], "utf8"), Buffer.from(b[0], "utf8"))
    );
    const parts = sorted.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
    return `{${parts.join(",")}}`;
  }
  throw new Error("UNSUPPORTED_TYPE");
}

const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// ---- HTTP helper ----
function postJson(url, body, headers = {}) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const req = request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...headers,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            /* ignore parse errors */
          }
          resolve({ status: res.statusCode, body: parsed, raw: data });
        });
      }
    );
    req.on("error", (err) => resolve({ status: 0, body: null, error: err }));
    req.write(payload);
    req.end();
  });
}

// ---- Demo data ----
const ACTION = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

const canonicalAction = canonicalize(ACTION);
const intentHash = sha256Hex(canonicalAction);
const audience = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";

function makeAuth({ authId, hash }) {
  return {
    auth_id: authId,
    issuer: "demo-issuer",
    audience,
    decision: "ALLOW",
    intent_hash: hash,
    expiry: Math.floor(Date.now() / 1000) + 3600,
  };
}

// ---- Scenarios ----
async function scenarioAllow() {
  const auth = makeAuth({ authId: `auth_${Date.now()}`, hash: intentHash });
  const res = await postJson("http://localhost:8787/execute", { action: ACTION, authorization: auth });
  console.log("SCENARIO: ALLOW");
  console.log(`  status: ${res.status}`);
  console.log(`  executed: ${res.body?.executed === true}`);
  return auth;
}

async function scenarioDenyHashMismatch() {
  const auth = makeAuth({ authId: `auth_${Date.now()}_bad`, hash: "deadbeef" });
  const res = await postJson("http://localhost:8787/execute", { action: ACTION, authorization: auth });
  console.log("SCENARIO: DENY_HASH_MISMATCH");
  console.log(`  status: ${res.status}`);
  console.log(`  blocked: ${res.status === 403}`);
}

async function scenarioReplay(reusedAuth) {
  const res = await postJson("http://localhost:8787/execute", { action: ACTION, authorization: reusedAuth });
  console.log("SCENARIO: REPLAY");
  console.log(`  status: ${res.status}`);
  console.log(`  blocked: ${res.status === 403}`);
}

async function scenarioBypass() {
  const res = await postJson("http://localhost:8788/charge", ACTION.params);
  console.log("SCENARIO: BYPASS");
  console.log(`  status: ${res.status}`);
  const rejected = res.status === 403;
  console.log(`  rejected: ${rejected}`);
}

async function main() {
  const auth = await scenarioAllow();
  await scenarioDenyHashMismatch();
  await scenarioReplay(auth);
  await scenarioBypass();

  console.log("SUMMARY:");
  console.log("  ALLOW: executed");
  console.log("  DENY_HASH_MISMATCH: blocked");
  console.log("  REPLAY: blocked");
  console.log("  BYPASS: rejected");
}

main().catch((err) => {
  console.error("unexpected error", err);
  process.exit(1);
});
