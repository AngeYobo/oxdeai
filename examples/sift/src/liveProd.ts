// SPDX-License-Identifier: Apache-2.0
/**
 * Live Sift production authorization helpers.
 *
 * All network I/O lives here.  run-prod.ts imports these helpers and
 * handles user-facing output.
 *
 * The prod path adds two steps compared to staging:
 *   fetchProdChallenge()   — fetch a nonce from /api/v1/auth/challenge
 *   signAuthorizeRequest() — sign the request body with the agent's Ed25519 key
 *
 * What is LIVE (requires network):
 *   fetchProdChallenge()      → real HTTPS to Sift prod challenge endpoint
 *   callProdAuthorize()       → real HTTPS POST to Sift prod authorize
 *   verifyWithProdKeyStore()  → real JWKS/KRL fetch + Ed25519 verify
 *
 * What remains LOCAL:
 *   pepVerify()               — OxDeAI PEP enforcement, in-memory replay
 *
 * Trust model:
 *   Sift decides → OxDeAI enforces at the PEP boundary.
 *   A verified Sift artifact is NOT execution authorization.
 *   It must still pass pepVerify() before anything executes.
 *
 * ── PLACEHOLDERS ──────────────────────────────────────────────────────────────
 *
 * The following values must be provided by Jason before prod can run:
 *
 *   PROD_JWKS_URL           — prod JWKS endpoint URL (not yet confirmed)
 *   ProdConfig.tenantId     — prod tenant identifier
 *   ProdConfig.agentId      — agent identifier registered with Sift prod
 *   ProdConfig.agentRole    — agent role (confirm if required by prod policy)
 *   ProdConfig.audience     — prod PEP audience string
 *   ProdConfig.publicKeyKid — key id for the prod agent keypair
 *   Policy IDs              — smoke test policy IDs for prod
 *   Private key path        — SIFT_PROD_PRIVATE_KEY_PATH or explicit path
 *
 * Challenge request/response shape (fetchProdChallenge) is isolated in its own
 * section and must be updated if Jason provides different field names.
 *
 * Authorize request shape (buildProdAuthorizeUnsignedBody) is isolated similarly.
 */

import { readFileSync } from "node:fs";
import { SiftHttpKeyStore } from "@oxdeai/sift";
import type { AuthorizationV1Payload, OxDeAIIntent, NormalizedState } from "@oxdeai/sift";
import { canonicalHash, signCanonical, verifyCanonical } from "./helpers.js";

// ─── Prod endpoints ───────────────────────────────────────────────────────────

export const PROD_BASE_URL       = "https://sift.walkosystems.com";
export const PROD_CHALLENGE_URL  = `${PROD_BASE_URL}/api/v1/auth/challenge`;
export const PROD_AUTHORIZE_URL  = `${PROD_BASE_URL}/api/v1/authorize`;
export const PROD_KRL_URL        = `${PROD_BASE_URL}/api/v1/krl`;
export const PROD_HEALTH_URL     = `${PROD_BASE_URL}/api/v1/health`;
export const PROD_VERIFY_KEY_URL = `${PROD_BASE_URL}/api/v1/receipt/verify-key`;

// PLACEHOLDER: Prod JWKS URL not yet confirmed by Jason.
// Expected pattern (mirrors staging): https://sift.walkosystems.com/sift-jwks.json
// Update PROD_CONFIG_DEFAULTS.jwksUrl when Jason provides the value.
export const PROD_JWKS_URL_PLACEHOLDER = "PLACEHOLDER_PROD_JWKS_URL";

// ─── Configuration ────────────────────────────────────────────────────────────

/**
 * All prod-specific inputs in one struct.
 *
 * Fields marked PLACEHOLDER must be filled before prod can run.
 * URL overrides default to the known prod endpoints above.
 */
export interface ProdConfig {
  // PLACEHOLDER: provided by Jason
  tenantId: string;
  // PLACEHOLDER: provided by Jason
  agentId: string;
  // PLACEHOLDER: confirm with Jason whether prod policy requires this field
  agentRole?: string;
  // PLACEHOLDER: prod PEP audience string (e.g. "oxdeai-pep-prod"); confirm with Jason
  audience: string;
  // PLACEHOLDER: prod JWKS endpoint URL; confirm with Jason
  jwksUrl: string;
  // Agent Ed25519 private key (PEM, PKCS8).  Load via loadProdPrivateKey().
  privateKeyPem: string;
  // URL overrides (optional; default to PROD_* constants above)
  challengeUrl?: string;
  authorizeUrl?: string;
  krlUrl?: string;
  // Logging metadata only — not used in any cryptographic operation
  // PLACEHOLDER: confirm kid value with Jason
  publicKeyKid?: string;
  // base64url-no-padding 32-byte Ed25519 public key x; for log confirmation only
  publicKeyX?: string;
}

// ─── Private key loader ───────────────────────────────────────────────────────

/**
 * Reads the agent's Ed25519 private key (PKCS8 PEM) from disk.
 *
 * Fails closed: throws if the file is missing or does not begin with a PEM header.
 *
 * Suggested default: resolve(".local/keys/oxdeai-prod-agent-ed25519-private.pem")
 * from the project root.  Set SIFT_PROD_PRIVATE_KEY_PATH to override.
 * The private key file must never be committed.
 */
export function loadProdPrivateKey(filePath: string): string {
  let pem: string;
  try {
    pem = readFileSync(filePath, "utf8");
  } catch (e) {
    throw new Error(
      `prod private key not found at "${filePath}": ` +
        `${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (!pem.includes("-----BEGIN")) {
    throw new Error(
      `prod private key at "${filePath}" does not look like a PEM file`,
    );
  }
  return pem;
}

// ─── Result types ─────────────────────────────────────────────────────────────

export type ProdAuthorizeResult =
  | {
      ok: true;
      decision: string;
      auth_id: string;
      policy_id: string;
      issuer: string;
      signingKeyRaw: Uint8Array;
      /**
       * Populated only when decision === "ALLOW".
       * Typed as AuthorizationV1Payload for direct use with pepVerify().
       * null for DENY / REPLAY responses.
       */
      allowArtifact: AuthorizationV1Payload | null;
    }
  | { ok: false; error: string };

// ─── Challenge endpoint ───────────────────────────────────────────────────────
//
// PLACEHOLDER: Shape is isolated below.  Update if Jason provides different
// field names for the challenge request or response.

interface ProdChallengeRequest {
  tenant_id: string;
  agent_id: string;
}

interface ProdChallengeResponse {
  nonce: string;
}

/**
 * Fetches a one-time nonce from the Sift prod challenge endpoint.
 *
 * PLACEHOLDER: Challenge request and response shapes are assumptions based on
 * the endpoint contract.  Confirm with Jason before running prod.
 *
 * Fails closed on any network error, non-2xx response, or malformed body.
 */
export async function fetchProdChallenge(
  config: ProdConfig,
): Promise<{ ok: true; nonce: string } | { ok: false; error: string }> {
  const url = config.challengeUrl ?? PROD_CHALLENGE_URL;

  const body: ProdChallengeRequest = {
    tenant_id: config.tenantId,
    agent_id: config.agentId,
  };

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return {
      ok: false,
      error: `challenge network error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  if (!response.ok) {
    let detail = "";
    try {
      const rb = (await response.json()) as Record<string, unknown>;
      detail = typeof rb["message"] === "string" ? `: ${rb["message"]}` : "";
    } catch { /* ignore */ }
    return { ok: false, error: `HTTP ${response.status} from challenge endpoint${detail}` };
  }

  let raw: unknown;
  try {
    raw = (await response.json()) as unknown;
  } catch {
    return { ok: false, error: "could not parse challenge response as JSON" };
  }

  // PLACEHOLDER: Response shape assumed to be { nonce: string }.
  // Update the field path below if Jason provides a different shape
  // (e.g. { data: { nonce: string } } or { challenge: string }).
  const parsed = parseChallengeResponse(raw);
  if ("error" in parsed) {
    return { ok: false, error: `malformed challenge response: ${parsed.error}` };
  }
  return { ok: true, nonce: parsed.nonce };
}

function parseChallengeResponse(
  raw: unknown,
): ProdChallengeResponse | { error: string } {
  if (typeof raw !== "object" || raw === null) {
    return { error: "challenge response is not a JSON object" };
  }
  const r = raw as Record<string, unknown>;
  if (typeof r["nonce"] !== "string" || r["nonce"].length === 0) {
    return { error: "missing or empty field: nonce" };
  }
  return { nonce: r["nonce"] as string };
}

// ─── Authorize request shape ──────────────────────────────────────────────────
//
// PLACEHOLDER: Field names and required set for the prod authorize request are
// assumptions.  Confirm with Jason before running prod.  Only buildProdAuthorizeUnsignedBody
// and signAuthorizeRequest need to change if the shape differs.

interface ProdAuthorizeUnsignedBody {
  // Staging-identical fields
  audience: string;
  decision: string;
  policy_id: string;
  intent: OxDeAIIntent;
  intent_hash: string;
  state: NormalizedState;
  state_hash: string;
  // PLACEHOLDER: Prod-specific fields (assumed; confirm with Jason)
  tenant_id: string;
  agent_id: string;
  nonce: string;
  agent_role?: string;
}

export interface ProdAuthorizeSignedBody extends ProdAuthorizeUnsignedBody {
  // Ed25519 over Sift-canonical(body-minus-request_sig), base64url-no-padding
  request_sig: string;
}

/**
 * Constructs the authorize request body WITHOUT the agent signature.
 *
 * PLACEHOLDER: Prod-specific fields (tenant_id, agent_id, nonce, agent_role)
 * are present based on expected contract.  Confirm shape with Jason.
 */
export function buildProdAuthorizeUnsignedBody(
  intent: OxDeAIIntent,
  state: NormalizedState,
  decision: string,
  policyId: string,
  nonce: string,
  config: ProdConfig,
): ProdAuthorizeUnsignedBody {
  const body: ProdAuthorizeUnsignedBody = {
    audience: config.audience,
    decision,
    policy_id: policyId,
    intent,
    intent_hash: canonicalHash(intent),
    state,
    state_hash: canonicalHash(state),
    tenant_id: config.tenantId,
    agent_id: config.agentId,
    nonce,
  };
  if (config.agentRole !== undefined) {
    body.agent_role = config.agentRole;
  }
  return body;
}

/**
 * Signs the authorize request body with the agent's Ed25519 private key.
 *
 * Preimage: Sift-canonical JSON of the unsigned body (all fields except
 * request_sig).  The signature covers the nonce so each signed request is
 * unique.
 *
 * Returns a new object that includes all original fields plus request_sig.
 *
 * PLACEHOLDER: Confirm the preimage convention with Jason.  If the expected
 * preimage differs (e.g. a subset of fields), update this function only.
 */
export function signAuthorizeRequest(
  unsignedBody: ProdAuthorizeUnsignedBody,
  privateKeyPem: string,
): ProdAuthorizeSignedBody {
  const request_sig = signCanonical(unsignedBody, privateKeyPem);
  return { ...unsignedBody, request_sig };
}

// ─── Network call ─────────────────────────────────────────────────────────────

/**
 * POSTs the signed authorize request to the Sift prod endpoint.
 * Returns the raw parsed JSON on success; does not validate shape.
 */
export async function callProdAuthorize(
  signedBody: ProdAuthorizeSignedBody,
  config: ProdConfig,
): Promise<{ ok: true; raw: unknown } | { ok: false; error: string }> {
  const url = config.authorizeUrl ?? PROD_AUTHORIZE_URL;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(signedBody),
    });
  } catch (e) {
    return {
      ok: false,
      error: `authorize network error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  if (!response.ok) {
    let detail = "";
    try {
      const rb = (await response.json()) as Record<string, unknown>;
      detail = typeof rb["message"] === "string" ? `: ${rb["message"]}` : "";
    } catch { /* ignore */ }
    return { ok: false, error: `HTTP ${response.status} from prod authorize${detail}` };
  }

  let raw: unknown;
  try {
    raw = (await response.json()) as unknown;
  } catch {
    return { ok: false, error: "could not parse authorize response as JSON" };
  }

  return { ok: true, raw };
}

// ─── Response shape validation ────────────────────────────────────────────────

interface ParsedArtifact {
  version: string;
  auth_id: string;
  issuer: string;
  audience: string;
  decision: string;
  intent_hash: string;
  state_hash: string;
  policy_id: string;
  issued_at: number;
  expires_at: number;
  signature: { alg: string; kid: string; sig: string };
}

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/**
 * Validates and extracts the prod authorize response artifact.
 *
 * Accepts the same wire shape as staging: the artifact may be wrapped in an
 * "authorization" envelope or present at the top level.  Fails closed on any
 * missing or malformed field.
 */
export function parseProdAuthorizeResponse(
  raw: unknown,
): ParsedArtifact | { error: string } {
  const wrapper =
    typeof raw === "object" && raw !== null
      ? (raw as Record<string, unknown>)
      : null;

  const r =
    wrapper?.["authorization"] !== undefined
      ? wrapper["authorization"]
      : raw;

  if (typeof r !== "object" || r === null) {
    return { error: "authorization field is not a JSON object" };
  }
  const a = r as Record<string, unknown>;

  for (const k of [
    "version", "auth_id", "issuer", "audience", "decision",
    "intent_hash", "state_hash", "policy_id",
  ] as const) {
    if (!nonEmpty(a[k])) return { error: `missing or empty field: ${k}` };
  }
  if (typeof a["issued_at"]  !== "number") return { error: "missing issued_at" };
  if (typeof a["expires_at"] !== "number") return { error: "missing expires_at" };

  const sig = a["signature"];
  if (typeof sig !== "object" || sig === null) return { error: "missing signature object" };
  const s = sig as Record<string, unknown>;
  for (const k of ["alg", "kid", "sig"] as const) {
    if (!nonEmpty(s[k])) return { error: `missing signature.${k}` };
  }

  return {
    version:     a["version"]     as string,
    auth_id:     a["auth_id"]     as string,
    issuer:      a["issuer"]      as string,
    audience:    a["audience"]    as string,
    decision:    a["decision"]    as string,
    intent_hash: a["intent_hash"] as string,
    state_hash:  a["state_hash"]  as string,
    policy_id:   a["policy_id"]   as string,
    issued_at:   a["issued_at"]   as number,
    expires_at:  a["expires_at"]  as number,
    signature: {
      alg: s["alg"] as string,
      kid: s["kid"] as string,
      sig: s["sig"] as string,
    },
  };
}

// ─── JWKS/KRL verification ────────────────────────────────────────────────────

async function verifyWithProdKeyStore(
  artifact: ParsedArtifact,
  config: ProdConfig,
): Promise<{ ok: true; keyRaw: Uint8Array } | { ok: false; error: string }> {
  const keyStore = new SiftHttpKeyStore({
    jwksUrl: config.jwksUrl,
    krlUrl: config.krlUrl ?? PROD_KRL_URL,
  });

  try {
    await keyStore.refresh();
  } catch (e) {
    return {
      ok: false,
      error: `prod key store refresh failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  const { kid, sig } = artifact.signature;

  if (await keyStore.isKidRevoked(kid)) {
    return { ok: false, error: `signing key revoked: kid=${kid}` };
  }

  const keyRaw = await keyStore.getPublicKeyByKid(kid);
  if (!keyRaw) {
    return { ok: false, error: `unknown prod signing key: kid=${kid}` };
  }

  // Preimage: artifact with signature.sig absent.
  // signature.alg and signature.kid must remain — AuthorizationV1 contract.
  const preimage = {
    version:     artifact.version,
    auth_id:     artifact.auth_id,
    issuer:      artifact.issuer,
    audience:    artifact.audience,
    decision:    artifact.decision,
    intent_hash: artifact.intent_hash,
    state_hash:  artifact.state_hash,
    policy_id:   artifact.policy_id,
    issued_at:   artifact.issued_at,
    expires_at:  artifact.expires_at,
    signature:   { alg: artifact.signature.alg, kid: artifact.signature.kid },
  };

  if (!verifyCanonical(preimage, sig, Buffer.from(keyRaw))) {
    return { ok: false, error: "Ed25519 signature verification failed (prod key)" };
  }

  return { ok: true, keyRaw };
}

// ─── Main prod authorize ──────────────────────────────────────────────────────

/**
 * Full production authorization path:
 *   1. Fetch nonce from /api/v1/auth/challenge
 *   2. Build authorize request body with intent_hash + state_hash + nonce
 *   3. Sign request body with agent Ed25519 private key
 *   4. POST signed body to /api/v1/authorize
 *   5. Parse response shape (unwrap "authorization" envelope)
 *   6. Verify Ed25519 signature via prod JWKS/KRL
 *   7. Verify hash binding (response hashes match local computation)
 *   8. Return verified result; populate allowArtifact only if decision=ALLOW
 *
 * Fails closed: any step failure returns { ok: false }.
 * allowArtifact (when present) is NOT execution authorization — it must
 * still pass pepVerify() before anything executes.
 */
export async function prodAuthorize(
  intent: OxDeAIIntent,
  state: NormalizedState,
  decision: string,
  policyId: string,
  config: ProdConfig,
): Promise<ProdAuthorizeResult> {
  // 1. Fetch challenge nonce
  const challengeResult = await fetchProdChallenge(config);
  if (!challengeResult.ok) {
    return { ok: false, error: challengeResult.error };
  }
  const { nonce } = challengeResult;

  // 2. Build unsigned request body (includes intent_hash + state_hash)
  const unsignedBody = buildProdAuthorizeUnsignedBody(
    intent, state, decision, policyId, nonce, config,
  );

  // 3. Sign with agent's Ed25519 private key
  const signedBody = signAuthorizeRequest(unsignedBody, config.privateKeyPem);

  // 4. POST to prod authorize
  const callResult = await callProdAuthorize(signedBody, config);
  if (!callResult.ok) return { ok: false, error: callResult.error };

  // 5. Shape validation
  const parsed = parseProdAuthorizeResponse(callResult.raw);
  if ("error" in parsed) {
    return { ok: false, error: `malformed prod response: ${parsed.error}` };
  }

  // 6. JWKS/KRL + Ed25519 signature verification
  const verifyResult = await verifyWithProdKeyStore(parsed, config);
  if (!verifyResult.ok) return { ok: false, error: verifyResult.error };

  // 7. Hash binding — proves Sift signed over the exact intent/state we sent
  const localIntentHash = canonicalHash(intent);
  const localStateHash  = canonicalHash(state);

  if (parsed.intent_hash !== localIntentHash) {
    return {
      ok: false,
      error: `intent_hash mismatch: local=${localIntentHash} remote=${parsed.intent_hash}`,
    };
  }
  if (parsed.state_hash !== localStateHash) {
    return {
      ok: false,
      error: `state_hash mismatch: local=${localStateHash} remote=${parsed.state_hash}`,
    };
  }

  // 8. Return verified result; allowArtifact only when ALLOW
  const allowArtifact: AuthorizationV1Payload | null =
    parsed.decision === "ALLOW"
      ? {
          version:     "AuthorizationV1",
          auth_id:     parsed.auth_id,
          issuer:      parsed.issuer,
          audience:    parsed.audience,
          decision:    "ALLOW",
          intent_hash: parsed.intent_hash,
          state_hash:  parsed.state_hash,
          policy_id:   parsed.policy_id,
          issued_at:   parsed.issued_at,
          expires_at:  parsed.expires_at,
          signature: {
            alg: "ed25519",
            kid: parsed.signature.kid,
            sig: parsed.signature.sig,
          },
        }
      : null;

  return {
    ok: true,
    decision:     parsed.decision,
    auth_id:      parsed.auth_id,
    policy_id:    parsed.policy_id,
    issuer:       parsed.issuer,
    signingKeyRaw: verifyResult.keyRaw,
    allowArtifact,
  };
}
