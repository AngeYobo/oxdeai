// examples/non-bypassable-demo/pep-gateway.mjs
// Demo entry point for the reusable @oxdeai/guard PEP gateway.

import {
  createHttpUpstreamExecutor,
  createPepGatewayHttpServer,
} from "../../packages/guard/dist/index.js";
import { DEMO_KEYSET } from "./auth-fixture.mjs";

const PORT = Number(process.env.PORT || 8787);
const AUDIENCE = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";
const UPSTREAM_TOKEN = process.env.UPSTREAM_EXECUTOR_TOKEN;
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 8788);
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 1000);

if (!UPSTREAM_TOKEN) {
  console.error("[pep-gateway] missing required env UPSTREAM_EXECUTOR_TOKEN");
  process.exit(1);
}

const server = createPepGatewayHttpServer({
  expectedAudience: AUDIENCE,
  expectedIssuer: DEMO_KEYSET.issuer,
  trustedKeySets: [DEMO_KEYSET],
  internalExecutorToken: UPSTREAM_TOKEN,
  timeoutMs: UPSTREAM_TIMEOUT_MS,
  executeUpstream: createHttpUpstreamExecutor({
    port: UPSTREAM_PORT,
    path: "/charge",
  }),
});

server.listen(PORT, () => {
  console.log(`[pep-gateway] listening on :${PORT}`);
  console.log(`[pep-gateway] expects audience=${AUDIENCE}`);
  console.log("[pep-gateway] using reusable @oxdeai/guard gateway enforcement");
});
