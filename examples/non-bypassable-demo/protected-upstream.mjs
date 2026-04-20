// examples/non-bypassable-demo/protected-upstream.mjs
// Demo entry point for the reusable @oxdeai/guard upstream token boundary.

import { createProtectedUpstreamHttpServer } from "../../packages/guard/dist/index.js";

const PORT = Number(process.env.PORT || 8788);
const EXPECTED_TOKEN = process.env.UPSTREAM_EXECUTOR_TOKEN;
const TEST_DELAY_MS = Number(process.env.UPSTREAM_TEST_DELAY_MS || 2000);

if (!EXPECTED_TOKEN) {
  console.error("[protected-upstream] missing required env UPSTREAM_EXECUTOR_TOKEN");
  process.exit(1);
}

const server = createProtectedUpstreamHttpServer({
  path: "/charge",
  expectedToken: EXPECTED_TOKEN,
  execute: async (payload) => {
    const body = payload && typeof payload === "object" ? payload : {};

    if (body.__upstream_behavior === "error") {
      throw new Error("simulated upstream error");
    }
    if (body.__upstream_behavior === "timeout") {
      await new Promise((resolve) => setTimeout(resolve, TEST_DELAY_MS));
      return { ok: true, executed: true, route: "upstream", delayed: true };
    }

    return {
      ok: true,
      executed: true,
      route: "upstream",
      charge_id: `ch_${Date.now()}`,
      amount: body.amount,
      currency: body.currency,
      user_id: body.user_id,
    };
  },
});

server.listen(PORT, () => {
  console.log(`[protected-upstream] listening on :${PORT}`);
  console.log("[protected-upstream] using reusable @oxdeai/guard internal-token enforcement");
});
