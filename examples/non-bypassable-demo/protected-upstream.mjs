// examples/non-bypassable-demo/protected-upstream.mjs
// Demonstrates a protected upstream that cannot be called directly without the gateway-only secret.
// It trusts only the internal executor token; all other requests are rejected.

import { createServer } from "node:http";

const PORT = Number(process.env.PORT || 8788);
const EXPECTED_TOKEN = process.env.UPSTREAM_EXECUTOR_TOKEN;
const REQ_TOKEN_HEADER = "x-internal-executor-token";

if (!EXPECTED_TOKEN) {
  console.error("[protected-upstream] missing required env UPSTREAM_EXECUTOR_TOKEN");
  process.exit(1);
}

const json = (res, status, body) => {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
};

const server = createServer((req, res) => {
  const token = req.headers[REQ_TOKEN_HEADER];
  const forbid = () =>
    json(res, 403, { ok: false, error: "direct access forbidden: missing or invalid internal executor token" });

  if (req.method === "GET" && req.url === "/healthz") {
    return json(res, 200, { ok: true, route: "upstream", status: "healthy" });
  }

  if (req.method === "POST" && req.url === "/charge") {
    if (token !== EXPECTED_TOKEN) return forbid();

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      let payload = {};
      try {
        if (body.trim()) payload = JSON.parse(body);
      } catch {
        return json(res, 400, { ok: false, error: "invalid JSON" });
      }

      const { amount, currency, user_id } = payload;
      const chargeId = `ch_${Date.now()}`;

      return json(res, 200, {
        ok: true,
        executed: true,
        route: "upstream",
        charge_id: chargeId,
        amount,
        currency,
        user_id,
      });
    });
    return;
  }

  json(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => {
  console.log(`[protected-upstream] listening on :${PORT}`);
  console.log(`[protected-upstream] requires header ${REQ_TOKEN_HEADER} to match UPSTREAM_EXECUTOR_TOKEN (not logged)`);
});
