// SPDX-License-Identifier: Apache-2.0
/**
 * OxDeAI Sift Integration Demo
 *
 * Demonstrates the full path from a Sift receipt to a PEP execution decision.
 *
 * Architectural invariants:
 *   - Sift is the decision layer.  A receipt is evidence that a Sift policy
 *     engine evaluated a requested action — not execution authorization.
 *   - OxDeAI is the authorization and enforcement boundary.  Execution requires
 *     a signed AuthorizationV1 artifact issued only after local receipt
 *     verification, intent normalization, and state normalization all succeed.
 *   - The PEP is the execution gate.  Replay is enforced there, not in the
 *     adapter.
 *   - The system fails closed: any unresolvable ambiguity blocks execution.
 *
 * Wire format (Sift contract):
 *   - Canonical JSON: Python json.dumps(sort_keys=True, separators=(",",":"),
 *     ensure_ascii=True) — non-ASCII UTF-16 code units are \uXXXX-escaped.
 *   - Signatures: Ed25519 over Sift-canonical bytes, encoded as base64url
 *     without padding (RFC 4648 §5).
 *   - Public keys: raw 32-byte Ed25519 key material, matching the JWKS `x`
 *     field (RFC 8037 OKP).  No PEM wrapper needed at this boundary.
 *
 * Three scenarios:
 *   1. ALLOW  — valid receipt, valid intent, valid state, fresh authorization
 *   2. DENY   — DENY receipt blocked at the receipt verification boundary
 *   3. REPLAY — same authorization reused; PEP replay store blocks execution
 */

import {
  verifyReceipt,
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
} from "@oxdeai/sift";
import {
  makeKeyPair,
  buildMockReceipt,
  signAuthorization,
  pepVerify,
} from "./helpers.js";

// ─── Demo constants ──────────────────────────────────────────────────────────

const AUDIENCE = "demo-pep.oxdeai.local";
const ISSUER   = "sift-demo-issuer.oxdeai.local";
const KEY_ID   = "demo-issuer-key-1";

// ─── Key material  (generated once, shared across scenarios) ─────────────────

// Sift signing key — simulates the key held by the Sift governance service.
// In production this key is fetched from the Sift JWKS endpoint; the caller
// selects the entry whose `kid` matches the receipt's kid field and checks
// the KRL (Key Revocation List) before trusting the key.
const siftKeypair = makeKeyPair();

// OxDeAI issuer key — simulates the adapter issuer that signs AuthorizationV1.
const issuerKeypair = makeKeyPair();

// ─── Output helpers ──────────────────────────────────────────────────────────

function step(msg: string): void  { console.log(`  ${msg}`); }
function blank(): void            { console.log(); }

// ─────────────────────────────────────────────────────────────────────────────

console.log("OxDeAI Sift Integration Demo");
blank();

// Display key material in JWKS x format so the wire format is observable.
console.log("Key material (JWKS x, base64url no-padding):");
step(`sift key  kid=sift-demo-key-1    x=${siftKeypair.publicKeyJwksX}`);
step(`issuer key kid=${KEY_ID}  x=${issuerKeypair.publicKeyJwksX}`);
blank();

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 1 — ALLOW
//
// Full happy path: receipt → intent → state → authorization → PEP → execute.
// ═══════════════════════════════════════════════════════════════════════════

console.log("Scenario 1 — ALLOW");

// 1. Build a valid ALLOW receipt (simulates arrival from Sift).
const allowRawReceipt = buildMockReceipt({ decision: "ALLOW", keypair: siftKeypair });

// 2. Verify the receipt locally — structural, version, receipt_hash integrity,
//    Ed25519 signature, decision, freshness (in that order).
//    publicKeyRaw is the raw 32-byte key matching the JWKS `x` field.
const verifyAllowResult = verifyReceipt(allowRawReceipt, {
  publicKeyRaw: siftKeypair.publicKeyRaw,
});
if (!verifyAllowResult.ok) {
  step(`receipt verification: FAILED (${verifyAllowResult.code})`);
  step("executed: false");
  process.exit(1);
}
step("receipt verification: OK");
const receipt = verifyAllowResult.receipt;

// 3. Normalize intent from explicit runtime params.
//    The receipt binds the tool and action; params supply the call arguments.
const intentResult = normalizeIntent({
  receipt,
  params: { query: "SELECT logs WHERE user_id = ?", limit: 100 },
  expectedAction: "call_tool",
  expectedTool: "query_database",
});
if (!intentResult.ok) {
  step(`intent normalization: FAILED (${intentResult.code})`);
  step("executed: false");
  process.exit(1);
}
step("intent normalization: OK");
const intent = intentResult.intent;

// 4. Normalize runtime state.
const stateResult = normalizeState({
  state: { user_role: "operator", session_active: true, mfa_verified: true },
  requiredKeys: ["user_role"],
});
if (!stateResult.ok) {
  step(`state normalization: FAILED (${stateResult.code})`);
  step("executed: false");
  process.exit(1);
}
step("state normalization: OK");
const state = stateResult.state;

// 5. Construct the AuthorizationV1 payload.
//    Binds receipt.nonce → auth_id, policy_matched → policy_id,
//    computes intent_hash and state_hash with Sift-canonical JSON
//    (ensure_ascii=True), sets issued_at / expires_at.
const authResult = receiptToAuthorization({
  receipt,
  intent,
  state,
  issuer: ISSUER,
  audience: AUDIENCE,
  keyId: KEY_ID,
  ttlSeconds: 30,
  now: new Date(),
});
if (!authResult.ok) {
  step(`authorization construction: FAILED (${authResult.code})`);
  step("executed: false");
  process.exit(1);
}

// 6. Sign the signingPayload with the demo issuer key.
//    signingPayload is the authorization with signature.sig absent — the
//    correct preimage per the Sift contract.  signAuthorization fills
//    authorization.signature.sig with a base64url-no-padding Ed25519 signature.
const signedAuthorization = signAuthorization(
  authResult.authorization,
  authResult.signingPayload,
  issuerKeypair.privateKeyPem,
);

// 7. PEP enforcement — the execution boundary.
//    Checks in order: audience, expiry, Ed25519 signature, intent_hash,
//    state_hash, replay.  issuerPublicKeyRaw is the raw 32-byte key.
const pep1 = pepVerify({
  authorization: signedAuthorization,
  intent,
  state,
  audience: AUDIENCE,
  issuerPublicKeyRaw: issuerKeypair.publicKeyRaw,
  now: new Date(),
});

step(`authorization issued: auth_id=${signedAuthorization.auth_id}`);
step(`pep decision: ${pep1.decision}`);
step(`executed: ${String(pep1.executed)}`);

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 2 — DENY
//
// A DENY receipt is blocked at receipt verification.
// receiptToAuthorization and the PEP are never reached.
// ═══════════════════════════════════════════════════════════════════════════

blank();
console.log("Scenario 2 — DENY");

const denyRawReceipt = buildMockReceipt({ decision: "DENY", keypair: siftKeypair });

// requireAllowDecision defaults to true — DENY receipts are rejected here.
const verifyDenyResult = verifyReceipt(denyRawReceipt, {
  publicKeyRaw: siftKeypair.publicKeyRaw,
});

if (!verifyDenyResult.ok) {
  step(`receipt verification: ${verifyDenyResult.code}`);
  step("executed: false");
} else {
  // Unreachable with default requireAllowDecision; included for completeness.
  step("receipt verification: unexpected OK on DENY receipt");
  step("executed: false");
}

// ═══════════════════════════════════════════════════════════════════════════
// Scenario 3 — REPLAY
//
// The authorization from Scenario 1 is reused verbatim.
// The PEP replay store has already recorded auth_id from Scenario 1 and
// rejects the second attempt.  No re-issuance, no re-verification.
// ═══════════════════════════════════════════════════════════════════════════

blank();
console.log("Scenario 3 — REPLAY");

const pep3 = pepVerify({
  authorization: signedAuthorization,    // same artifact — already consumed
  intent,
  state,
  audience: AUDIENCE,
  issuerPublicKeyRaw: issuerKeypair.publicKeyRaw,
  now: new Date(),
});

step(`authorization reused: auth_id=${signedAuthorization.auth_id}`);
step(`pep decision: ${pep3.decision}`);
if (!pep3.ok) step(`reason: ${pep3.reason}`);
step(`executed: ${String(pep3.executed)}`);

blank();
