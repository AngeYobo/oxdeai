import { InMemoryStateAdapter, InMemoryAuditAdapter } from "@oxdeai/sdk";

import { makeEngine, makeState, AGENT_ID, DEMO_POST_ID } from "./policy.js";
import { createAgentgramGuard } from "./adapter.js";
import { AGENTGRAM_INTENTS } from "./intents.js";

const guard = createAgentgramGuard({
  engine: makeEngine(),
  agentId: AGENT_ID,
  stateAdapter: new InMemoryStateAdapter(makeState()),
  auditAdapter: new InMemoryAuditAdapter(),
});

async function run(): Promise<void> {
  const cases: Array<{ label: string; fn: () => Promise<unknown> }> = [
    // ── ALLOW cases ────────────────────────────────────────────────────────────
    {
      label: AGENTGRAM_INTENTS.READ_HOME,
      fn: () =>
        guard(
          { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 1n },
          async () => ({ home: [{ id: DEMO_POST_ID, caption: "Hello world" }] })
        ),
    },
    {
      label: AGENTGRAM_INTENTS.READ_FEED,
      fn: () =>
        guard(
          { tool: AGENTGRAM_INTENTS.READ_FEED, nonce: 2n },
          async () => ({ feed: [{ id: DEMO_POST_ID, caption: "Hello world" }] })
        ),
    },
    {
      label: AGENTGRAM_INTENTS.POST_LIKE,
      fn: () =>
        guard(
          { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: DEMO_POST_ID, nonce: 3n },
          async () => ({ liked: true, postId: DEMO_POST_ID })
        ),
    },
    {
      label: AGENTGRAM_INTENTS.COMMENT_CREATE,
      fn: () =>
        guard(
          {
            tool: AGENTGRAM_INTENTS.COMMENT_CREATE,
            postId: DEMO_POST_ID,
            content: "Nice post!",
            nonce: 4n,
          },
          async () => ({ created: true, postId: DEMO_POST_ID })
        ),
    },

    // ── DENY cases ─────────────────────────────────────────────────────────────

    // Replay: nonce 1n was already consumed by read_home above.
    {
      label: `${AGENTGRAM_INTENTS.READ_HOME} [replay nonce=1n]`,
      fn: () =>
        guard(
          { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: 1n },
          async () => ({ home: [] })
        ),
    },

    // Target mismatch: postId "post-unknown" is not in the state allowlist.
    {
      label: `${AGENTGRAM_INTENTS.POST_LIKE} [unknown postId]`,
      fn: () =>
        guard(
          { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: "post-unknown", nonce: 5n },
          async () => ({ liked: true, postId: "post-unknown" })
        ),
    },
  ];

  for (const { label, fn } of cases) {
    try {
      await fn();
      console.log(`ALLOW  ${label}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`DENY   ${label} | ${msg}`);
    }
  }
}

run().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
