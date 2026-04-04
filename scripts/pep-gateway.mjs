#!/usr/bin/env node
import http from "node:http";
import crypto from "node:crypto";
import { URL } from "node:url";

/**
* Minimal PEP Gateway
*
* Goals:
* - 1 file
* - no external deps
* - testable in 10 minutes
* - execution only reachable through authorization check
*
* Demo mode:
* - decision is accepted only if:
* authorization.decision === "ALLOW"
* authorization.intent_hash === sha256(canonical(action))
*
* Replace verifyAuthorizationArtifact() later with real OxDeAI verification.
*/

const PORT = Number(process.env.PORT || 8787);
const MAX_BODY_BYTES = 1024 * 1024;
const DEMO_MODE = process.env.DEMO_MODE !== "false";

// in-memory replay store for demo
const consumedAuthIds = new Set();

/* ----------------------------- Canonicalization ---------------------------- */

function normalizeString(value) {
return value.normalize("NFC");
}

function isPlainObject(value) {
return Object.prototype.toString.call(value) === "[object Object]";
}

function canonicalize(value) {
return Buffer.from(canonicalizeToJson(value), "utf8");
}

function canonicalizeToJson(value) {
if (value === null) return "null";

const t = typeof value;

if (t === "string") {
return JSON.stringify(normalizeString(value));
}

if (t === "boolean") {
return value ? "true" : "false";
}

if (t === "number") {
if (!Number.isInteger(value)) {
throw new Error("FLOAT_NOT_ALLOWED");
}
if (!Number.isSafeInteger(value)) {
throw new Error("UNSAFE_INTEGER_NUMBER");
}
return String(value);
}

if (t === "bigint") {
return JSON.stringify(String(value));
}

if (t === "undefined" || t === "function" || t === "symbol") {
throw new Error("UNSUPPORTED_TYPE");
}

if (Array.isArray(value)) {
return `[${value.map((item) => canonicalizeToJson(item)).join(",")}]`;
}

if (isPlainObject(value)) {
const keys = Object.keys(value).map(normalizeString).sort((a, b) => {
return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
});

const seen = new Set();
const parts = [];

for (const normalizedKey of keys) {
if (seen.has(normalizedKey)) {
throw new Error("DUPLICATE_KEY");
}
seen.add(normalizedKey);

// recover original value by exact normalized-key match
const originalEntry = Object.entries(value).find(
([k]) => normalizeString(k) === normalizedKey
);
if (!originalEntry) {
throw new Error("KEY_RESOLUTION_FAILED");
}

const [, child] = originalEntry;
parts.push(
`${JSON.stringify(normalizedKey)}:${canonicalizeToJson(child)}`
);
}

return `{${parts.join(",")}}`;
}

throw new Error("UNSUPPORTED_TYPE");
}

function sha256Hex(buf) {
return crypto.createHash("sha256").update(buf).digest("hex");
}

function computeIntentHash(action) {
const canonical = canonicalize(action);
return sha256Hex(canonical);
}

/* ------------------------------ Demo verifier ------------------------------ */

/**
* Real integration point:
* Replace this whole function with your real OxDeAI verifier path.
*
* Minimum expected behavior:
* - validate artifact shape
* - verify signature / issuer / audience / expiry / auth_id / policy binding
* - ensure authorization.decision === "ALLOW"
* - compare authorization.intent_hash to computed intent hash
* - fail closed on any ambiguity
*/
function verifyAuthorizationArtifact({ authorization, action, gatewayAudience }) {
try {
if (!authorization || typeof authorization !== "object") {
return deny("AUTHORIZATION_MISSING", "authorization is required");
}

if (authorization.decision !== "ALLOW") {
return deny("DECISION_NOT_ALLOW", "authorization decision is not ALLOW");
}

if (typeof authorization.auth_id !== "string" || authorization.auth_id.length === 0) {
return deny("AUTH_ID_MISSING", "auth_id is required");
}

if (consumedAuthIds.has(authorization.auth_id)) {
return deny("AUTH_REPLAY", "authorization has already been consumed");
}

if (typeof authorization.expiry !== "number" || !Number.isInteger(authorization.expiry)) {
return deny("EXPIRY_INVALID", "expiry must be an integer unix timestamp");
}

const now = Math.floor(Date.now() / 1000);
if (authorization.expiry <= now) {
return deny("AUTH_EXPIRED", "authorization has expired");
}

if (typeof authorization.audience !== "string" || authorization.audience !== gatewayAudience) {
return deny("AUDIENCE_MISMATCH", "authorization audience does not match gateway");
}

const computedIntentHash = computeIntentHash(action);

if (
typeof authorization.intent_hash !== "string" ||
authorization.intent_hash !== computedIntentHash
) {
return deny("INTENT_HASH_MISMATCH", "action does not match authorized intent");
}

// DEMO MODE NOTE:
// no signature verification here yet
if (!DEMO_MODE) {
return deny(
"REAL_VERIFIER_REQUIRED",
"DEMO_MODE=false but no real verifier is configured"
);
}

return {
ok: true,
decision: "ALLOW",
reasonCode: "AUTHORIZED",
reason: "authorization verified",
computedIntentHash,
};
} catch (err) {
return deny("VERIFY_ERROR", err instanceof Error ? err.message : "verification failed");
}
}

/* ---------------------------- Protected execution -------------------------- */

async function protectedExecute(action) {
// Replace these handlers with real side effects later.
// The point is: nothing reaches here without successful auth.

if (!action || typeof action !== "object") {
throw new Error("INVALID_ACTION");
}

if (action.type !== "EXECUTE") {
throw new Error("UNSUPPORTED_ACTION_TYPE");
}

const tool = action.tool;
const params = action.params ?? {};

switch (tool) {
case "payments.charge":
return {
executed: true,
tool,
upstream_result: {
charge_id: `ch_${crypto.randomUUID()}`,
amount: params.amount,
currency: params.currency,
status: "captured",
},
};

case "infra.provision_vm":
return {
executed: true,
tool,
upstream_result: {
vm_id: `vm_${crypto.randomUUID()}`,
region: params.region ?? "eu-west-1",
size: params.size ?? "small",
status: "created",
},
};

default:
throw new Error(`UNKNOWN_TOOL:${tool}`);
}
}

/* --------------------------------- Server -------------------------------- */

function deny(reasonCode, reason, extra = {}) {
return {
ok: false,
decision: "DENY",
reasonCode,
reason,
...extra,
};
}

function json(res, status, payload) {
const body = Buffer.from(JSON.stringify(payload, null, 2), "utf8");
res.writeHead(status, {
"content-type": "application/json; charset=utf-8",
"content-length": body.length,
});
res.end(body);
}

async function readJsonBody(req) {
const chunks = [];
let total = 0;

for await (const chunk of req) {
total += chunk.length;
if (total > MAX_BODY_BYTES) {
throw new Error("BODY_TOO_LARGE");
}
chunks.push(chunk);
}

const raw = Buffer.concat(chunks).toString("utf8");
try {
return JSON.parse(raw);
} catch {
throw new Error("INVALID_JSON");
}
}

const gatewayAudience = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";

const server = http.createServer(async (req, res) => {
try {
const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

if (req.method === "GET" && url.pathname === "/healthz") {
return json(res, 200, {
ok: true,
service: "pep-gateway",
audience: gatewayAudience,
demo_mode: DEMO_MODE,
});
}

if (req.method === "POST" && url.pathname === "/execute") {
const body = await readJsonBody(req);
const action = body?.action;
const authorization = body?.authorization;

if (!action) {
return json(res, 400, deny("ACTION_MISSING", "action is required"));
}

// verify BEFORE execution
const verification = verifyAuthorizationArtifact({
authorization,
action,
gatewayAudience,
});

if (!verification.ok) {
return json(res, 403, {
...verification,
executed: false,
});
}

// consume auth_id only after verification succeeds and right before execution
consumedAuthIds.add(authorization.auth_id);

try {
const result = await protectedExecute(action);

return json(res, 200, {
ok: true,
decision: "ALLOW",
reasonCode: verification.reasonCode,
reason: verification.reason,
auth_id: authorization.auth_id,
intent_hash: verification.computedIntentHash,
...result,
});
} catch (err) {
return json(res, 502, {
ok: false,
decision: "DENY",
reasonCode: "UPSTREAM_EXECUTION_FAILED",
reason: err instanceof Error ? err.message : "execution failed",
executed: false,
});
}
}

return json(res, 404, deny("NOT_FOUND", "route not found"));
} catch (err) {
return json(res, 400, deny("REQUEST_ERROR", err instanceof Error ? err.message : "bad request"));
}
});

server.listen(PORT, () => {
console.log(`PEP Gateway listening on http://localhost:${PORT}`);
console.log(`Gateway audience: ${gatewayAudience}`);
console.log(`Demo mode: ${DEMO_MODE ? "ON" : "OFF"}`);
console.log(`Routes:
GET /healthz
POST /execute`);
});






