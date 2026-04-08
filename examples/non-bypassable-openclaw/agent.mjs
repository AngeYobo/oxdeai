import { createHash } from "node:crypto";

const fetchFn =
  globalThis.fetch ??
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const GATEWAY_URL = "http://localhost:8787/execute";
const DIRECT_URL  = "http://localhost:8788/charge";

const action = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

// --- Canonicalization (matches demo gateway) ---
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
  if (typeof value === "bigint") {
    if (value < SAFE_MIN || value > SAFE_MAX) throw new Error("UNSAFE_INTEGER_NUMBER");
    return JSON.stringify(String(value));
  }
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

const canonicalAction = canonicalize(action);
const intentHash = sha256Hex(canonicalAction);

const allowAuth = {
  auth_id: "auth-allow-1",
  issuer: "demo",
  audience: "pep-gateway.local",
  decision: "ALLOW",
  intent_hash: intentHash,
  expiry: Math.floor(Date.now() / 1000) + 600,
};

const denyAuth = { ...allowAuth, auth_id: "auth-deny-1", intent_hash: "bad" };
const replayAuth = allowAuth; // same id → replay after first use

async function scenario(name, auth) {
  const body = { action, authorization: auth };
  const res = await fetchFn(GATEWAY_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  console.log(`SCENARIO: ${name}`, res.status, json);
}

async function bypass() {
  const res = await fetchFn(DIRECT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(action.params),
  });
  console.log("SCENARIO: BYPASS", res.status, "(expected 403)");
}

(async () => {
  console.log("SCENARIO: ALLOW");
  await scenario("ALLOW", allowAuth);

  console.log("SCENARIO: DENY_HASH_MISMATCH");
  await scenario("DENY_HASH_MISMATCH", denyAuth);

  console.log("SCENARIO: REPLAY");
  await scenario("REPLAY", replayAuth);

  await bypass();
})();
