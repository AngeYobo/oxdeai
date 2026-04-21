// examples/non-bypassable-demo/pep-gateway.mjs
// Demonstrates non-bypassable gateway: no valid authorization -> no execution.
// Enforces intent binding, replay protection, and upstream secret isolation.

import { createServer, request } from "node:http";
import { createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.PORT || 8787);
const AUDIENCE = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";
const UPSTREAM_TOKEN = process.env.UPSTREAM_EXECUTOR_TOKEN;
const UPSTREAM_PORT = 8788;
const REPLAY_CACHE = new Set();

// --- Trusted public keys (loaded once at startup) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const KEYS_FILE =
  process.env.TRUSTED_KEYS_FILE ||
  resolve(__dirname, "../../docs/spec/test-vectors/authorization-v1.json");

let TRUSTED_KEYS;
try {
  const fixture = JSON.parse(readFileSync(KEYS_FILE, "utf8"));
  TRUSTED_KEYS = fixture.keys;
  if (!Array.isArray(TRUSTED_KEYS) || TRUSTED_KEYS.length === 0)
    throw new Error("no keys array found in fixture");
} catch (err) {
  console.error(`[pep-gateway] failed to load trusted keys from ${KEYS_FILE}: ${err.message}`);
  process.exit(1);
}

if (!UPSTREAM_TOKEN) {
  console.error("[pep-gateway] missing required env UPSTREAM_EXECUTOR_TOKEN");
  process.exit(1);
}

// --- Canonicalization (matches demo semantics) ---
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

// --- Verification helpers ---
const deny = (res, reason, extra = {}) => {
  const body = JSON.stringify({ ok: false, decision: "DENY", reason, ...extra });
  res.writeHead(403, { "content-type": "application/json; charset=utf-8" });
  res.end(body);
};

const json200 = (res, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
  res.end(body);
};

function isFutureUnix(ts) {
  return Number.isInteger(ts) && ts > Date.now() / 1000;
}

function verifyRequest(payload) {
  const { action, authorization } = payload || {};
  if (!authorization) return [false, "missing authorization"];
  if (authorization.decision !== "ALLOW") return [false, "decision not ALLOW"];
  if (!authorization.auth_id) return [false, "missing auth_id"];
  if (REPLAY_CACHE.has(authorization.auth_id)) return [false, "auth_id already used"];
  if (!isFutureUnix(authorization.expiry)) return [false, "authorization expired or invalid"];
  if (authorization.audience !== AUDIENCE) return [false, "audience mismatch"];

  // Signature verification — fail closed, runs before all hash checks
  const { signature } = authorization;
  if (
    !signature ||
    typeof signature.kid !== "string" ||
    typeof signature.alg !== "string" ||
    typeof signature.sig !== "string"
  ) {
    return [false, "authorization signature missing or malformed"];
  }
  const trustedKey = TRUSTED_KEYS.find(
    (k) => k.kid === signature.kid && k.alg === signature.alg
  );
  if (!trustedKey) return [false, `unknown kid: ${signature.kid}`];
  // Preimage: canonical form of the authorization artifact with the signature block removed.
  // Top-level alg and kid fields remain — only the nested signature object is excluded,
  // matching the convention used when the authorization was issued.
  const { signature: _sig, ...authPayload } = authorization;
  let authCanonical;
  try {
    authCanonical = canonicalize(authPayload);
  } catch (err) {
    return [false, `authorization canonicalization failed: ${err.message}`];
  }
  let sigValid;
  try {
    sigValid = verify(
      null,
      Buffer.from(authCanonical, "utf8"),
      trustedKey.public_key_pem,
      Buffer.from(signature.sig, "base64")
    );
  } catch (err) {
    return [false, `signature verification error: ${err.message}`];
  }
  if (!sigValid) return [false, "invalid authorization signature"];

  let canonical;
  try {
    canonical = canonicalize(action);
  } catch (err) {
    return [false, `canonicalization failed: ${err.message}`];
  }
  const intentHash = sha256Hex(canonical);
  if (authorization.intent_hash !== intentHash) return [false, "intent hash mismatch"];

  // State binding (fail-closed: missing state_hash or snapshot → DENY, hash mismatch → DENY)
  if (!authorization.state_hash) return [false, "authorization missing state_hash"];
  const { state_snapshot } = payload || {};
  if (!state_snapshot) return [false, "missing state_snapshot: state cannot be verified"];
  let computedStateHash;
  try {
    computedStateHash = sha256Hex(canonicalize(state_snapshot));
  } catch (err) {
    return [false, `state canonicalization failed: ${err.message}`];
  }
  if (computedStateHash !== authorization.state_hash) return [false, "state hash mismatch"];

  return [true, null, { canonical, intentHash, authId: authorization.auth_id }];
}

// --- Upstream call ---
function callUpstream(params, cb) {
  const body = JSON.stringify(params || {});
  const req = request(
    {
      hostname: "localhost",
      port: UPSTREAM_PORT,
      path: "/charge",
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
        "x-internal-executor-token": UPSTREAM_TOKEN,
      },
    },
    (resp) => {
      let data = "";
      resp.on("data", (c) => (data += c));
      resp.on("end", () => {
        try {
          cb(null, resp.statusCode, data ? JSON.parse(data) : {});
        } catch (e) {
          cb(e);
        }
      });
    }
  );
  req.on("error", (err) => cb(err));
  req.write(body);
  req.end();
}

// --- Server ---
const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/healthz") {
    return json200(res, { ok: true, route: "gateway", status: "healthy" });
  }

  if (req.method === "POST" && req.url === "/execute") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let payload;
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        return deny(res, "invalid JSON");
      }

      const [ok, reason, info] = verifyRequest(payload);
      if (!ok) return deny(res, reason);

      // Passed checks: enforce replay protection now
      REPLAY_CACHE.add(info.authId);

      callUpstream(payload.action?.params, (err, status, upstream) => {
        if (err || (status && status >= 400)) {
          return deny(res, "upstream error", { upstream_error: err?.message || upstream });
        }
        return json200(res, {
          ok: true,
          decision: "ALLOW",
          executed: true,
          auth_id: info.authId,
          intent_hash: info.intentHash,
          upstream_result: upstream,
        });
      });
    });
    return;
  }

  res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ ok: false, error: "not found" }));
});

server.listen(PORT, () => {
  console.log(`[pep-gateway] listening on :${PORT}`);
  console.log(`[pep-gateway] expects audience=${AUDIENCE}`);
  console.log(`[pep-gateway] upstream token kept internal; direct calls to upstream will be refused`);
});
