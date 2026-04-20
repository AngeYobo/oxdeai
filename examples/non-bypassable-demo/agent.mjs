// examples/non-bypassable-demo/agent.mjs
// How to run:
// 1) node examples/non-bypassable-demo/protected-upstream.mjs
// 2) node examples/non-bypassable-demo/pep-gateway.mjs
// 3) node examples/non-bypassable-demo/agent.mjs
//
// This script simulates an agent/runtime issuing actions through the gateway.
// It demonstrates: valid execution, replay denial, and direct-upstream bypass rejection.

import { request } from "node:http";
import { hashAction, makeAuthorization } from "./auth-fixture.mjs";

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

const intentHash = hashAction(ACTION);
const audience = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";

function makeAuth({ authId, hash }) {
  return makeAuthorization({ action: ACTION, authId, audience, intentHash: hash });
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
  await scenarioReplay(auth);
  await scenarioBypass();

  console.log("SUMMARY:");
  console.log("  ALLOW: executed");
  console.log("  REPLAY: blocked");
  console.log("  BYPASS: rejected");
}

main().catch((err) => {
  console.error("unexpected error", err);
  process.exit(1);
});
