import { InMemoryStateAdapter, InMemoryAuditAdapter } from "@oxdeai/sdk";
import {
  makeLiveEngine,
  makeLiveState,
  DEFAULT_ENGINE_SECRET
} from "./policy-live.js";
import { createAgentgramGuard } from "./adapter.js";
import { AGENTGRAM_INTENTS } from "./intents.js";
import {
  registerAgent,
  fetchMemory,
  getHome,
  getFeed,
  likePost,
  commentOnPost
} from "./client.js";

async function safeJson(res: Response): Promise<unknown> {
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) return null;
  return res.json().catch(() => null);
}

function extractApiKey(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;

  const search = (o: Record<string, unknown>) => {
    for (const k of ["api_key", "apiKey", "token", "key"]) {
      if (typeof o[k] === "string") return o[k] as string;
    }
    return null;
  };

  const b = body as Record<string, unknown>;
  return (
    search(b) ??
    (b.data && typeof b.data === "object"
      ? search(b.data as Record<string, unknown>)
      : null)
  );
}

function extractPostIds(body: unknown): string[] {
  if (!body || typeof body !== "object") return [];

  const b = body as Record<string, unknown>;
  const data =
    b.data && typeof b.data === "object"
      ? (b.data as Record<string, unknown>)
      : null;

  const candidates = [
    b.posts,
    b.feed,
    b.home,
    b.items,
    data?.posts,
    data?.feed,
    data?.home,
    data?.items
  ];

  const source = candidates.find(Array.isArray) ?? [];

  return (source as unknown[])
    .map((p) =>
      p && typeof p === "object"
        ? ((p as Record<string, unknown>).id as string | undefined)
        : undefined
    )
    .filter((id): id is string => typeof id === "string");
}

function extractMemory(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;

  const b = body as Record<string, unknown>;
  const data =
    b.data && typeof b.data === "object"
      ? (b.data as Record<string, unknown>)
      : null;

  const containers = [b, data].filter(Boolean) as Record<string, unknown>[];

  for (const container of containers) {
    for (const k of ["memories", "entries", "items"]) {
      const arr = container[k];
      if (Array.isArray(arr) && arr.length > 0) {
        const first = arr[0];
        if (typeof first === "string" && first.trim()) return first.trim();
        if (first && typeof first === "object") {
          const val =
            (first as Record<string, unknown>).text ??
            (first as Record<string, unknown>).content ??
            (first as Record<string, unknown>).observation;
          if (typeof val === "string" && val.trim()) return val.trim();
        }
      }
    }

    for (const k of ["memory", "content", "text", "social_context"]) {
      const val = container[k];
      if (typeof val === "string" && val.trim()) return val.trim();
    }
  }

  return null;
}

async function runLive(): Promise<void> {
  const agentNameEnv = process.env.AGENTGRAM_AGENT_NAME;
  const targetAgentNameEnv = process.env.AGENTGRAM_TARGET_AGENT_NAME;

  if (!agentNameEnv) {
    throw new Error("Missing required env: AGENTGRAM_AGENT_NAME");
  }

  if (!targetAgentNameEnv) {
    throw new Error("Missing required env: AGENTGRAM_TARGET_AGENT_NAME");
  }

  const agentName = agentNameEnv;
  const targetAgentName = targetAgentNameEnv;

  const agentDescription =
    process.env.AGENTGRAM_AGENT_DESCRIPTION ?? "OxDeAI live sandbox agent";
  const targetPostIdEnv = process.env.AGENTGRAM_TARGET_POST_ID;
  const engineSecret = process.env.OXDEAI_ENGINE_SECRET;

  if (!engineSecret) {
    console.warn(
      `Warning: OXDEAI_ENGINE_SECRET not set, using default: ${DEFAULT_ENGINE_SECRET}`
    );
  }

  let nonce = 1n;
  const nextNonce = () => nonce++;
  const now = () => Math.floor(Date.now() / 1000);

  function makeGuard(postIds: string[]) {
    return createAgentgramGuard({
      engine: makeLiveEngine(engineSecret),
      agentId: agentName,
      stateAdapter: new InMemoryStateAdapter(
        makeLiveState({
          agentId: agentName,
          targetAgentName,
          postIds
        })
      ),
      auditAdapter: new InMemoryAuditAdapter()
    });
  }

  let apiKey = process.env.AGENTGRAM_API_KEY ?? "";

  console.log("OxDeAI x Agentgram live sandbox");
  console.log(`Agent: ${agentName}`);
  console.log(`Target agent for memory: ${targetAgentName}`);

  if (!apiKey) {
    console.log("\nPhase A  Bootstrap");

    const guard = makeGuard([]);

    const registerBody = await guard(
      {
        tool: AGENTGRAM_INTENTS.REGISTER_AGENT,
        agentName,
        description: agentDescription,
        nonce: nextNonce(),
        timestampSeconds: now()
      },
      async () => {
        const res = await registerAgent(agentName, agentDescription);
        if (!res.ok) {
          throw new Error(`register_agent failed: HTTP ${res.status}`);
        }
        return safeJson(res);
      }
    );

    const extractedKey = extractApiKey(registerBody);
    if (!extractedKey) {
      throw new Error(
        "Bootstrap failed: registration response did not contain an API key."
      );
    }

    apiKey = extractedKey;
    console.log("ALLOW  register_agent");
    console.log(`Registered. Save this now: AGENTGRAM_API_KEY=${apiKey}`);
  } else {
    console.log("\nPhase A  Bootstrap skipped, AGENTGRAM_API_KEY already present");
  }

  const clientConfig = { apiKey };

  console.log("\nPhase B  Discovery");

  const guardB = makeGuard([]);
  const discoveredPostIds: string[] = [];

  const homeBody = await guardB(
    {
      tool: AGENTGRAM_INTENTS.READ_HOME,
      nonce: nextNonce(),
      timestampSeconds: now()
    },
    async () => {
      const res = await getHome(clientConfig);
      if (!res.ok) {
        throw new Error(`read_home failed: HTTP ${res.status}`);
      }
      return safeJson(res);
    }
  );
  console.log("ALLOW  read_home");
  discoveredPostIds.push(...extractPostIds(homeBody));

  const feedBody = await guardB(
    {
      tool: AGENTGRAM_INTENTS.READ_FEED,
      nonce: nextNonce(),
      timestampSeconds: now()
    },
    async () => {
      const res = await getFeed(clientConfig);
      if (!res.ok) {
        throw new Error(`read_feed failed: HTTP ${res.status}`);
      }
      return safeJson(res);
    }
  );
  console.log("ALLOW  read_feed");
  discoveredPostIds.push(...extractPostIds(feedBody));

  const targetPostId = targetPostIdEnv ?? discoveredPostIds[0];
  if (!targetPostId) {
    throw new Error(
      "No target post found. Set AGENTGRAM_TARGET_POST_ID or ensure /feed or /home returns posts."
    );
  }
  console.log(`Selected post: ${targetPostId}`);

  const memoryBody = await guardB(
    {
      tool: AGENTGRAM_INTENTS.FETCH_MEMORY,
      agentName: targetAgentName,
      nonce: nextNonce(),
      timestampSeconds: now()
    },
    async () => {
      const res = await fetchMemory(clientConfig, targetAgentName);
      if (!res.ok && res.status !== 404) {
        throw new Error(`fetch_memory failed: HTTP ${res.status}`);
      }
      return safeJson(res);
    }
  );
  console.log("ALLOW  fetch_memory");

  const memoryText = extractMemory(memoryBody);
  const commentContent = memoryText
    ? `${memoryText.slice(0, 120)} — via OxDeAI`
    : "Interesting post! (no memory context)";
  console.log(`Comment preview: ${commentContent}`);

  console.log("\nPhase C  Interaction");

  const guardC = makeGuard([targetPostId]);

  await guardC(
    {
      tool: AGENTGRAM_INTENTS.POST_LIKE,
      postId: targetPostId,
      nonce: nextNonce(),
      timestampSeconds: now()
    },
    async () => {
      const res = await likePost(clientConfig, targetPostId);

      if (res.status === 409) {
        return {
          status: "already_liked",
          postId: targetPostId
        };
      }

      if (!res.ok) {
        throw new Error(`like_post failed: HTTP ${res.status}`);
      }

      return safeJson(res);
    }
  );
  console.log(`ALLOW  like_post (${targetPostId})`);
  console.log("       downstream status: executed or already liked");

  await guardC(
    {
      tool: AGENTGRAM_INTENTS.COMMENT_CREATE,
      postId: targetPostId,
      content: commentContent,
      nonce: nextNonce(),
      timestampSeconds: now()
    },
    async () => {
      const res = await commentOnPost(clientConfig, targetPostId, commentContent);
      if (!res.ok) {
        throw new Error(`comment_post failed: HTTP ${res.status}`);
      }
      return safeJson(res);
    }
  );
  console.log(`ALLOW  comment_post (${targetPostId})`);

  console.log("\nPhase D  Replay");

  const replayNonce = 999n;

  await guardC(
    {
      tool: AGENTGRAM_INTENTS.READ_HOME,
      nonce: replayNonce,
      timestampSeconds: now()
    },
    async () => {
      const res = await getHome(clientConfig);
      if (!res.ok) {
        throw new Error(`read_home failed: HTTP ${res.status}`);
      }
      return safeJson(res);
    }
  );
  console.log("ALLOW  read_home (first use of replay test nonce)");

  try {
    await guardC(
      {
        tool: AGENTGRAM_INTENTS.READ_HOME,
        nonce: replayNonce,
        timestampSeconds: now()
      },
      async () => {
        const res = await getHome(clientConfig);
        if (!res.ok) {
          throw new Error(`read_home failed: HTTP ${res.status}`);
        }
        return safeJson(res);
      }
    );

    console.log("ERROR  replay_nonce should have been denied");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`DENY   replay_nonce | ${msg}`);
  }

  console.log("\nPhase E  Invalid target");

  try {
    await guardC(
      {
        tool: AGENTGRAM_INTENTS.POST_LIKE,
        postId: "invalid-post-id",
        nonce: nextNonce(),
        timestampSeconds: now()
      },
      async () => {
        const res = await likePost(clientConfig, "invalid-post-id");
        if (!res.ok) {
          throw new Error(`like_post failed: HTTP ${res.status}`);
        }
        return safeJson(res);
      }
    );

    console.log("ERROR  allowlist_target should have been denied");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`DENY   allowlist_target | ${msg}`);
  }

  console.log("\nLive run complete");
}

runLive().catch((err) => {
  console.error("Live run failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});