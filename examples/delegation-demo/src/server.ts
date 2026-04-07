// SPDX-License-Identifier: Apache-2.0
/**
 * server.ts - Minimal HTTP server for the delegation demo.
 *
 * GET /        → serves the two-panel demo UI (src/index.html)
 * GET /events  → returns the pre-computed scenario steps as JSON
 *
 * Usage: node dist/server.js  (via pnpm -C examples/delegation-demo start)
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runScenario } from "./scenario.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// index.html lives in src/ (not compiled - served at runtime from source)
const HTML_PATH = path.join(__dirname, "../src/index.html");
const PORT = 3334;

async function main(): Promise<void> {
  console.log("\nRunning OxDeAI delegation scenario...");
  const steps = await runScenario();

  const decisions = steps.filter(s => s.auth).map(s => `${s.auth!.agentId}:${s.auth!.decision}`);
  console.log(`Scenario complete: ${decisions.join(" → ")}`);

  // BigInt values in scenario steps need custom JSON serialization
  const eventsJson = JSON.stringify(steps, (_key, value) =>
    typeof value === "bigint" ? value.toString() : value
  );
  const html = fs.readFileSync(HTML_PATH, "utf8");

  const server = http.createServer((req, res) => {
    if (req.url === "/events" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(eventsJson);
    } else {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    }
  });

  server.listen(PORT, () => {
    const url = `http://localhost:${PORT}`;
    console.log(`\nOxDeAI - Delegation Demo`);
    console.log(`Open: ${url}\n`);

    import("node:child_process").then(({ spawn }) => {
      const cmd = process.platform === "darwin" ? "open"
                : process.platform === "win32"  ? "start"
                : "xdg-open";
      spawn(cmd, [url], { stdio: "ignore", detached: true }).unref();
    }).catch(() => { /* browser open is best-effort */ });
  });
}

main().catch(err => {
  console.error("Demo server failed:", err);
  process.exit(1);
});
