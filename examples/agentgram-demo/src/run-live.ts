import { InMemoryStateAdapter, InMemoryAuditAdapter } from "@oxdeai/sdk";
import {
  makeLiveEngine,
  makeLiveState
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

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  yellow:  "\x1b[33m",
  bCyan:   "\x1b[1;36m",
  bGreen:  "\x1b[1;32m",
  bRed:    "\x1b[1;31m",
  bYellow: "\x1b[1;33m",
  bWhite:  "\x1b[1;97m",
};
const c = (col: string, txt: string) => `${col}${txt}${C.reset}`;

// ── Layout ────────────────────────────────────────────────────────────────────
const W   = Math.max(86, (process.stdout.columns ?? 120) - 2);
const COL = Math.floor((W - 7) / 2);

function vlen(s: string): number {
  return s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").length;
}
function pad(s: string, width: number): string {
  return s + " ".repeat(Math.max(0, width - vlen(s)));
}
function center(s: string, width: number): string {
  const total = Math.max(0, width - vlen(s));
  const l = Math.floor(total / 2);
  return " ".repeat(l) + s + " ".repeat(total - l);
}

// ── Box primitives ────────────────────────────────────────────────────────────
const TOP = c(C.cyan, "╔" + "═".repeat(W - 2) + "╗");
const MID = c(C.cyan, "╠" + "═".repeat(W - 2) + "╣");
const DIV = c(C.cyan, "╟" + "─".repeat(W - 2) + "╢");
const BOT = c(C.cyan, "╚" + "═".repeat(W - 2) + "╝");

function row(left: string, right: string): string {
  return (
    c(C.cyan, "║") + " " +
    pad(left,  COL) + " " +
    c(C.dim,  "│") + " " +
    pad(right, COL) + " " +
    c(C.cyan, "║")
  );
}
function full(text: string): string {
  return c(C.cyan, "║") + " " + pad(text, W - 4) + " " + c(C.cyan, "║");
}
function emit(line: string): void {
  process.stdout.write(line + "\n");
}

// ── Display helpers ───────────────────────────────────────────────────────────
function printHeader(agentName: string, targetAgentName: string): void {
  process.stdout.write("\x1b[2J\x1b[H");
  emit(TOP);
  emit(full(center(c(C.bWhite, "OxDeAI × Agentgram  —  Live Sandbox"), W - 4)));
  emit(full(c(C.dim, `  agent: ${agentName}  ·  memory target: ${targetAgentName}`)));
  emit(full(c(C.dim, `   trust: explicit keyset required  ·  no trust → no execution`)));
  emit(MID);
  emit(row(c(C.bCyan, "AGENT ACTIONS"), c(C.bCyan, "AUTHORIZATION")));
  emit(MID);
}

function printPhase(label: string): void {
  emit(DIV);
  emit(full(c(C.bYellow, `  ${label}`)));
  emit(DIV);
}

function printAllow(action: string, detail?: string): void {
  const right = c(C.bGreen, "✓ ALLOW") +
    (detail ? "  " + c(C.dim, detail.slice(0, COL - 10)) : "");
  emit(row(c(C.cyan, `→ ${action}`), right));
}

function printAllowSub(sub: string): void {
  emit(row(c(C.dim, `    ${sub.slice(0, COL - 4)}`), ""));
}

function printDeny(action: string, reason: string): void {
  const badge = c(C.bRed, "✗ DENY");
  emit(row(
    c(C.red, `✗ ${action}`),
    badge + "  " + c(C.dim, reason.slice(0, COL - 10))
  ));
}

function printInfo(text: string): void {
  emit(full(c(C.dim, `    ${text.slice(0, W - 8)}`)));
}


function printFooter(ok: boolean): void {
  emit(DIV);
  emit(full(ok
    ? c(C.bGreen, "  ✓  Live run complete")
    : `\x1b[1;31;5m  ✗  Live run failed${C.reset}`
  ));
  emit(BOT);
}

// ── JSON helpers ──────────────────────────────────────────────────────────────
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
  const candidates = [b.posts, b.feed, b.home, b.items,
                      data?.posts, data?.feed, data?.home, data?.items];
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

// ── Main ──────────────────────────────────────────────────────────────────────
let headerPrinted = false;

async function runLive(): Promise<void> {
  const agentNameEnv      = process.env.AGENTGRAM_AGENT_NAME;
  const targetAgentNameEnv = process.env.AGENTGRAM_TARGET_AGENT_NAME;

  if (!agentNameEnv)
    throw new Error("Missing required env: AGENTGRAM_AGENT_NAME");
  if (!targetAgentNameEnv)
    throw new Error("Missing required env: AGENTGRAM_TARGET_AGENT_NAME");

  const agentName       = agentNameEnv;
  const targetAgentName = targetAgentNameEnv;
  const agentDescription =
    process.env.AGENTGRAM_AGENT_DESCRIPTION ?? "OxDeAI live sandbox agent";
  const targetPostIdEnv = process.env.AGENTGRAM_TARGET_POST_ID;
  const engineSecret    = process.env.OXDEAI_ENGINE_SECRET;

  printHeader(agentName, targetAgentName);
  headerPrinted = true;

  if (!engineSecret) {
    throw new Error("Missing required env var: OXDEAI_ENGINE_SECRET");
  }
  const secret: string = engineSecret;

  let nonce = 1n;
  const nextNonce = () => nonce++;
  const now       = () => Math.floor(Date.now() / 1000);

  function makeGuard(postIds: string[]) {
    return createAgentgramGuard({
      engine:       makeLiveEngine(secret),
      agentId:      agentName,
      stateAdapter: new InMemoryStateAdapter(
        makeLiveState({ agentId: agentName, targetAgentName, postIds })
      ),
      auditAdapter: new InMemoryAuditAdapter()
    });
  }

  let apiKey = process.env.AGENTGRAM_API_KEY ?? "";

  // ── Phase A: Bootstrap ────────────────────────────────────────────────────
  if (!apiKey) {
    printPhase("Phase A  —  Bootstrap");

    const guard = makeGuard([]);
    const registerBody = await guard(
      { tool: AGENTGRAM_INTENTS.REGISTER_AGENT, agentName, description: agentDescription,
        nonce: nextNonce(), timestampSeconds: now() },
      async () => {
        const res = await registerAgent(agentName, agentDescription);
        if (!res.ok) throw new Error(`register_agent failed: HTTP ${res.status}`);
        return safeJson(res);
      }
    );

    const extractedKey = extractApiKey(registerBody);
    if (!extractedKey)
      throw new Error("Bootstrap failed: registration response did not contain an API key.");

    apiKey = extractedKey;
    const redactedKey =
    apiKey.length > 18
        ? `${apiKey.slice(0, 12)}...${apiKey.slice(-4)}`
        : "[redacted]";

    printAllow("register_agent", "new agent created");
    printAllowSub(`api key issued: ${redactedKey}`);
  } else {
    printPhase("Phase A  —  Bootstrap");
    printInfo("AGENTGRAM_API_KEY present — registration skipped");
  }

  const clientConfig = { apiKey };

  // ── Phase B: Discovery ────────────────────────────────────────────────────
  printPhase("Phase B  —  Discovery");

  const guardB = makeGuard([]);
  const discoveredPostIds: string[] = [];

  const homeBody = await guardB(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: nextNonce(), timestampSeconds: now() },
    async () => {
      const res = await getHome(clientConfig);
      if (!res.ok) throw new Error(`read_home failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );
  printAllow("read_home", "authorized  ·  executed");
  discoveredPostIds.push(...extractPostIds(homeBody));

  const feedBody = await guardB(
    { tool: AGENTGRAM_INTENTS.READ_FEED, nonce: nextNonce(), timestampSeconds: now() },
    async () => {
      const res = await getFeed(clientConfig);
      if (!res.ok) throw new Error(`read_feed failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );
  printAllow("read_feed", "authorized  ·  executed");
  discoveredPostIds.push(...extractPostIds(feedBody));

  const targetPostId = targetPostIdEnv ?? discoveredPostIds[0];
  if (!targetPostId)
    throw new Error(
      "No target post found. Set AGENTGRAM_TARGET_POST_ID or ensure /feed returns posts."
    );
  printInfo(`target post: ${targetPostId.slice(0, 20)}...`);

  const memoryBody = await guardB(
    { tool: AGENTGRAM_INTENTS.FETCH_MEMORY, agentName: targetAgentName,
      nonce: nextNonce(), timestampSeconds: now() },
    async () => {
      const res = await fetchMemory(clientConfig, targetAgentName);
      if (!res.ok && res.status !== 404)
        throw new Error(`fetch_memory failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );

  const memoryText = extractMemory(memoryBody);
  const commentContent = memoryText
    ? `${memoryText.slice(0, 120)} — via OxDeAI`
    : "Interesting post! (no memory context)";
  printAllow(
    "fetch_memory",
    memoryText ? "authorized  ·  context found" : "authorized  ·  fallback mode"
  );
  printAllowSub(`comment preview: ${commentContent.slice(0, COL - 22)}`);

  // ── Phase C: Interaction ──────────────────────────────────────────────────
  printPhase("Phase C  —  Interaction");

  const guardC = makeGuard([targetPostId]);

  await guardC(
    { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: targetPostId,
      nonce: nextNonce(), timestampSeconds: now() },
    async () => {
      const res = await likePost(clientConfig, targetPostId);
      if (res.status === 409) return { status: "already_liked", postId: targetPostId };
      if (!res.ok) throw new Error(`like_post failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );
  printAllow("like_post", `authorized  ·  post=${targetPostId.slice(0, 12)}...`);
  printAllowSub("executed  ·  committed or already liked");

  await guardC(
    { tool: AGENTGRAM_INTENTS.COMMENT_CREATE, postId: targetPostId,
      content: commentContent, nonce: nextNonce(), timestampSeconds: now() },
    async () => {
      const res = await commentOnPost(clientConfig, targetPostId, commentContent);
      if (!res.ok) throw new Error(`comment_post failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );
  printAllow("comment_post", `authorized  ·  post=${targetPostId.slice(0, 12)}...`);
  printAllowSub("executed  ·  committed");

  // ── Phase D: Replay protection ────────────────────────────────────────────
  printPhase("Phase D  —  Replay protection");

  const replayNonce = 999n;

  await guardC(
    { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: replayNonce, timestampSeconds: now() },
    async () => {
      const res = await getHome(clientConfig);
      if (!res.ok) throw new Error(`read_home failed: HTTP ${res.status}`);
      return safeJson(res);
    }
  );
  printAllow("read_home", "authorized  ·  nonce 999 first use");

  try {
    await guardC(
      { tool: AGENTGRAM_INTENTS.READ_HOME, nonce: replayNonce, timestampSeconds: now() },
      async () => {
        const res = await getHome(clientConfig);
        if (!res.ok) throw new Error(`read_home failed: HTTP ${res.status}`);
        return safeJson(res);
      }
    );
    printDeny("read_home [replay]", "expected DENY — replay was not blocked");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    printDeny("read_home [replay]", msg);
  }

  // ── Phase E: Invalid target ───────────────────────────────────────────────
  printPhase("Phase E  —  Invalid target");

  try {
    await guardC(
      { tool: AGENTGRAM_INTENTS.POST_LIKE, postId: "invalid-post-id",
        nonce: nextNonce(), timestampSeconds: now() },
      async () => {
        const res = await likePost(clientConfig, "invalid-post-id");
        if (!res.ok) throw new Error(`like_post failed: HTTP ${res.status}`);
        return safeJson(res);
      }
    );
    printDeny("like_post [invalid]", "expected DENY — allowlist was not enforced");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    printDeny("like_post [invalid]", msg);
  }

  printFooter(true);
}

runLive().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  if (headerPrinted) {
    emit(DIV);
    emit(full(c(C.bRed, `  ✗  ${msg.slice(0, W - 8)}`)));
    printFooter(false);
  } else {
    process.stdout.write(`\x1b[1;31mLive run failed:\x1b[0m ${msg}\n`);
  }
  process.exit(1);
});
