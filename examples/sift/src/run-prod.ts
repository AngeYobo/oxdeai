// SPDX-License-Identifier: Apache-2.0
/**
 * OxDeAI Sift Production Smoke Test — ALLOW path + OxDeAI PEP replay check.
 *
 * Seven numbered steps, each printed OK or FAIL before the next runs.
 * Stops immediately on any failure.
 *
 * Run:
 *   pnpm -C examples/sift start:prod
 *
 * Debug mode (prints intermediate values at each step, never prints key material):
 *   SIFT_PROD_DEBUG=1 pnpm -C examples/sift start:prod
 *
 * Prerequisites (see README.md "Production smoke test"):
 *   - Private key:  .local/keys/oxdeai-prod-agent-ed25519-private.pem
 *   - Public key x: .local/keys/oxdeai-prod-agent-ed25519-public.x.txt
 *   or set SIFT_PROD_PRIVATE_KEY_PATH
 */

import { resolve } from "node:path";
import { readFileSync } from "node:fs";

import {
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
} from "@oxdeai/sift";

import { pepVerify, signAuthorization, decodeJwksX } from "./helpers.js";

import {
  loadProdPrivateKey,
  fetchProdChallenge,
  buildProdAuthorizeRequest,
  buildProdAuthorizeRequestDebug,
  callProdAuthorize,
  extractRawReceipt,
  fetchProdVerifyKey,
  verifySiftReceipt,
  PROD_CHALLENGE_URL,
  PROD_AUTHORIZE_URL,
  PROD_VERIFY_KEY_URL,
  type ProdConfig,
  type ProdAuthorizeRequest,
} from "./liveProd.js";

// ─── Debug helper ─────────────────────────────────────────────────────────────

const DEBUG = process.env["SIFT_PROD_DEBUG"] === "1";

function dbg(label: string, value: unknown): void {
  if (!DEBUG) return;
  const rendered =
    typeof value === "string"
      ? value
      : JSON.stringify(value, null, 2);
  console.log(`  [debug] ${label}:`);
  for (const line of rendered.split("\n")) {
    console.log(`    ${line}`);
  }
}

// ─── Local constants ──────────────────────────────────────────────────────────

const PEP_AUDIENCE  = "oxdeai-pep-prod";
const ISSUER        = "oxdeai-prod-smoke";
const ISSUER_KEY_ID = "oxdeai-prod-agent-key";

// ─── Key material ─────────────────────────────────────────────────────────────

const PRIVATE_KEY_PATH = process.env["SIFT_PROD_PRIVATE_KEY_PATH"]
  ?? resolve(process.cwd(), ".local/keys/oxdeai-prod-agent-ed25519-private.pem");

let privateKeyPem: string;
try {
  privateKeyPem = loadProdPrivateKey(PRIVATE_KEY_PATH);
} catch (e) {
  console.error(`ERROR: ${e instanceof Error ? e.message : String(e)}`);
  console.error(`Place the key at: ${PRIVATE_KEY_PATH}`);
  console.error(`or set: SIFT_PROD_PRIVATE_KEY_PATH`);
  process.exit(1);
}

let publicKeyX = "";
try {
  publicKeyX = readFileSync(
    resolve(process.cwd(), ".local/keys/oxdeai-prod-agent-ed25519-public.x.txt"),
    "utf8",
  ).trim();
} catch {
  console.error(
    "ERROR: public key x not found at " +
    ".local/keys/oxdeai-prod-agent-ed25519-public.x.txt\n" +
    "  This file must contain the base64url-encoded raw 32-byte Ed25519 public key."
  );
  process.exit(1);
}

let issuerPublicKeyRaw: Buffer;
try {
  issuerPublicKeyRaw = decodeJwksX(publicKeyX);
} catch (e) {
  console.error(`ERROR: failed to decode public key x: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}

// ─── Config ───────────────────────────────────────────────────────────────────

const config: ProdConfig = {
  tenantId:    "oxdeai_designpartner",
  agentId:     "oxdeai-boundary-demo-01",
  agentRole:   "validation_agent",
  privateKeyPem,
  publicKeyX,
  challengeUrl: PROD_CHALLENGE_URL,
  authorizeUrl: PROD_AUTHORIZE_URL,
  verifyKeyUrl: PROD_VERIFY_KEY_URL,
};

// ─── Smoke scenario params ────────────────────────────────────────────────────

const action   = "read";
const tool     = "web.search";
const riskTier = 1;
const params: Record<string, unknown> = { query: "site:oxdeai.com" };

// ─────────────────────────────────────────────────────────────────────────────

console.log("OxDeAI Sift Prod Smoke Test");
if (DEBUG) console.log("  [debug] SIFT_PROD_DEBUG=1 — verbose output enabled");
console.log();

// ── [1] Challenge ─────────────────────────────────────────────────────────────

const challengeResult = await fetchProdChallenge(config);
if (!challengeResult.ok) {
  console.log(`[1] challenge: FAIL — ${challengeResult.error}`);
  process.exit(1);
}
console.log("[1] challenge: OK");
dbg("challenge response shape", challengeResult.rawShape ?? {});
const nonce = challengeResult.nonce;

// ── [2] Request signing ───────────────────────────────────────────────────────

let request: ProdAuthorizeRequest;
try {
  if (DEBUG) {
    const d = buildProdAuthorizeRequestDebug(action, tool, riskTier, params, nonce, config);
    request = d.request;
    dbg("unsigned request body (params included, signature omitted)", {
      ...d.request,
      signature: "(computed below)",
    });
    dbg("signing preimage object", d.preimage);
    dbg("params_hash", d.paramsHash);
    dbg("canonical signing JSON (ensure_ascii=FALSE, sorted keys, no whitespace)", d.canonicalJson);
    dbg("signature (base64url, safe to share)", d.signature);
  } else {
    request = buildProdAuthorizeRequest(action, tool, riskTier, params, nonce, config);
  }
} catch (e) {
  console.log(`[2] request signing: FAIL — ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
console.log("[2] request signing: OK");

// ── [3] Authorize response ────────────────────────────────────────────────────

const authorizeResult = await callProdAuthorize(request, config);
if (!authorizeResult.ok) {
  console.log(`[3] authorize response: FAIL — ${authorizeResult.error}`);
  process.exit(1);
}
const rawReceipt = extractRawReceipt(authorizeResult.raw);
if (rawReceipt === null) {
  console.log("[3] authorize response: FAIL — could not extract receipt from response");
  process.exit(1);
}
console.log("[3] authorize response: OK");
if (DEBUG) {
  const topLevelKeys =
    typeof authorizeResult.raw === "object" && authorizeResult.raw !== null
      ? Object.keys(authorizeResult.raw as Record<string, unknown>)
      : [];
  dbg("authorize response top-level keys", topLevelKeys);
  dbg("extracted receipt top-level keys",
    typeof rawReceipt === "object" && rawReceipt !== null
      ? Object.keys(rawReceipt as Record<string, unknown>)
      : rawReceipt,
  );
}

// ── [4] Local receipt verification ───────────────────────────────────────────

const verifyKeyResult = await fetchProdVerifyKey(config);
if (!verifyKeyResult.ok) {
  console.log(`[4] local receipt verification: FAIL — ${verifyKeyResult.error}`);
  process.exit(1);
}
dbg("verify-key response shape",
  typeof verifyKeyResult.raw === "object" && verifyKeyResult.raw !== null
    ? Object.keys(verifyKeyResult.raw as Record<string, unknown>)
    : verifyKeyResult.raw,
);

const receiptVerification = verifySiftReceipt(rawReceipt, verifyKeyResult.raw, config.tenantId);
if (!receiptVerification.ok) {
  console.log(`[4] local receipt verification: FAIL — ${receiptVerification.code}`);
  dbg("local verification result", { ok: false, code: receiptVerification.code });
  process.exit(1);
}
console.log("[4] local receipt verification: OK");
dbg("local verification result", {
  ok:       true,
  decision: receiptVerification.receipt.decision,
  nonce:    receiptVerification.receipt.nonce,
  policy:   receiptVerification.receipt.policy_matched,
  tenant:   receiptVerification.receipt.tenant_id,
  agent:    receiptVerification.receipt.agent_id,
});
const receipt = receiptVerification.receipt;
dbg("policy mapping", { policy_id: receipt.policy_matched, source: "policy_hash" });

// ── [5] Authorization conversion ──────────────────────────────────────────────

const intentResult = normalizeIntent({
  receipt,
  params,
  expectedAction: action,
  expectedTool: tool,
});
if (!intentResult.ok) {
  console.log(`[5] authorization conversion: FAIL — intent normalization: ${intentResult.code}`);
  process.exit(1);
}

const stateResult = normalizeState({
  state: { agent: config.agentId, session_active: true },
  requiredKeys: [],
});
if (!stateResult.ok) {
  console.log(`[5] authorization conversion: FAIL — state normalization: ${stateResult.code}`);
  process.exit(1);
}

const authConvResult = receiptToAuthorization({
  receipt,
  intent:   intentResult.intent,
  state:    stateResult.state,
  issuer:   ISSUER,
  audience: PEP_AUDIENCE,
  keyId:    ISSUER_KEY_ID,
});
if (!authConvResult.ok) {
  console.log(`[5] authorization conversion: FAIL — ${authConvResult.code}`);
  process.exit(1);
}

const signedAuth = signAuthorization(
  authConvResult.authorization,
  authConvResult.signingPayload,
  privateKeyPem,
);
console.log("[5] authorization conversion: OK");
dbg("authorization payload (sig field present but elided here)", {
  auth_id:    signedAuth.auth_id,
  issuer:     signedAuth.issuer,
  audience:   signedAuth.audience,
  decision:   signedAuth.decision,
  intent_hash:signedAuth.intent_hash,
  state_hash: signedAuth.state_hash,
  policy_id:  signedAuth.policy_id,
  issued_at:  signedAuth.issued_at,
  expires_at: signedAuth.expires_at,
  "signature.kid": signedAuth.signature.kid,
  "signature.alg": signedAuth.signature.alg,
});

// ── [6] PEP decision ──────────────────────────────────────────────────────────

const pep = pepVerify({
  authorization: signedAuth,
  intent:        intentResult.intent,
  state:         stateResult.state,
  audience:      PEP_AUDIENCE,
  issuerPublicKeyRaw,
  now:           new Date(),
});
console.log(`[6] pep decision: ${pep.decision}`);
if (!pep.ok) {
  console.log(`    reason: ${pep.reason}`);
}
dbg("pep result", pep.ok
  ? { decision: pep.decision, executed: pep.executed, auth_id: pep.auth_id }
  : { decision: pep.decision, executed: pep.executed, reason: pep.reason },
);
if (!pep.ok) {
  process.exit(1);
}

// ── [7] Execution ─────────────────────────────────────────────────────────────

console.log(`[7] execution: ${String(pep.executed)}`);

// ── Replay Check — OxDeAI PEP ─────────────────────────────────────────────────
//
// Reuses the exact same signed artifact from the successful ALLOW above.
// No network call — the OxDeAI PEP enforces replay protection in-process via
// its in-memory auth_id store.  This is distinct from any Sift-side REPLAY
// decision: Sift is not contacted here.  The PEP sees the same auth_id it
// already recorded in step [6] and returns DENY / reason=REPLAY.
//
// Only runs when the initial ALLOW path fully succeeded.

if (pep.ok) {
  console.log();
  console.log("Replay Check — OxDeAI PEP");

  const pepReplay = pepVerify({
    authorization: signedAuth,
    intent:        intentResult.intent,
    state:         stateResult.state,
    audience:      PEP_AUDIENCE,
    issuerPublicKeyRaw,
    now:           new Date(),
  });

  console.log(`  first execution:  ALLOW / executed: true`);
  console.log(`  second execution: ${pepReplay.decision} / reason: ${!pepReplay.ok ? pepReplay.reason : "—"} / executed: ${String(pepReplay.executed)}`);
  dbg("replay pep result", !pepReplay.ok
    ? { decision: pepReplay.decision, reason: pepReplay.reason, executed: pepReplay.executed }
    : { decision: pepReplay.decision, executed: pepReplay.executed },
  );
  if (pepReplay.ok || pepReplay.reason !== "REPLAY" || pepReplay.executed) {
    console.log("  replay enforcement: FAIL");
    process.exit(1);
  }
  console.log("  replay enforcement: OK");
}
