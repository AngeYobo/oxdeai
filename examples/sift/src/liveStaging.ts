// SPDX-License-Identifier: Apache-2.0
/**
 * Live Sift staging authorization helpers.
 *
 * All network I/O lives here.  run-staging.ts imports these helpers and
 * handles user-facing output.
 *
 * Staging API contract discovered via probing:
 *   - Request body must include: audience, decision, policy_id, intent,
 *     intent_hash, state, state_hash
 *   - Response wraps the artifact under a top-level "authorization" key
 *   - Staging signs ALLOW, DENY, and REPLAY decisions on request
 *
 * What is LIVE (requires network):
 *   callStagingAuthorize()   → real HTTPS POST to Sift staging
 *   verifyWithKeyStore()     → real JWKS/KRL fetch + Ed25519 verify
 *
 * What remains LOCAL (in helpers.ts / run-staging.ts):
 *   pepVerify()              — OxDeAI PEP enforcement, in-memory replay
 *
 * Trust model:
 *   Sift decides → OxDeAI enforces at the PEP boundary.
 *   A verified Sift artifact is NOT execution authorization.
 *   It must still pass pepVerify() before anything executes.
 */

import { createStagingKeyStore } from "@oxdeai/sift";
import type { AuthorizationV1Payload, OxDeAIIntent, NormalizedState } from "@oxdeai/sift";
import { canonicalHash, verifyCanonical } from "./helpers.js";

// ─── Endpoints ────────────────────────────────────────────────────────────────

export const STAGING_AUTHORIZE_URL =
  "https://sift-staging.walkosystems.com/api/v1/authorize";

export const STAGING_AUDIENCE = "oxdeai-pep-staging";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AuthorizeRequestBody {
  audience: string;
  decision: string;     // caller specifies desired decision (ALLOW / DENY / REPLAY)
  policy_id: string;    // caller specifies which staging policy to invoke
  intent: OxDeAIIntent;
  intent_hash: string;
  state: NormalizedState;
  state_hash: string;
}

export type LiveAuthorizeResult =
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

// ─── Internal parsed artifact shape ──────────────────────────────────────────

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

// ─── Request builder ──────────────────────────────────────────────────────────

export function buildAuthorizeRequestBody(
  intent: OxDeAIIntent,
  state: NormalizedState,
  decision: string,
  policyId: string,
  audience: string = STAGING_AUDIENCE,
): AuthorizeRequestBody {
  return {
    audience,
    decision,
    policy_id: policyId,
    intent,
    intent_hash: canonicalHash(intent),
    state,
    state_hash: canonicalHash(state),
  };
}

// ─── Network call ─────────────────────────────────────────────────────────────

export async function callStagingAuthorize(
  body: AuthorizeRequestBody,
): Promise<{ ok: true; raw: unknown } | { ok: false; error: string }> {
  let response: Response;
  try {
    response = await fetch(STAGING_AUTHORIZE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return {
      ok: false,
      error: `network error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  if (!response.ok) {
    let detail = "";
    try {
      const body = (await response.json()) as Record<string, unknown>;
      detail = typeof body["message"] === "string" ? `: ${body["message"]}` : "";
    } catch { /* ignore */ }
    return { ok: false, error: `HTTP ${response.status} from staging${detail}` };
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

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function parseArtifact(raw: unknown): ParsedArtifact | { error: string } {
  // Response is wrapped: { authorization: {...}, debug: {...} }
  const wrapper =
    typeof raw === "object" && raw !== null
      ? (raw as Record<string, unknown>)
      : null;

  const r =
    wrapper?.["authorization"] !== undefined
      ? wrapper["authorization"]
      : raw; // fall back to top-level for forward-compatibility

  if (typeof r !== "object" || r === null) {
    return { error: "authorization field is not a JSON object" };
  }
  const a = r as Record<string, unknown>;

  for (const k of ["version","auth_id","issuer","audience","decision",
                   "intent_hash","state_hash","policy_id"] as const) {
    if (!nonEmpty(a[k])) return { error: `missing or empty field: ${k}` };
  }
  if (typeof a["issued_at"]  !== "number") return { error: "missing issued_at"  };
  if (typeof a["expires_at"] !== "number") return { error: "missing expires_at" };

  const sig = a["signature"];
  if (typeof sig !== "object" || sig === null) return { error: "missing signature object" };
  const s = sig as Record<string, unknown>;
  for (const k of ["alg","kid","sig"] as const) {
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

// ─── Signature verification via JWKS/KRL ─────────────────────────────────────

async function verifyWithKeyStore(
  artifact: ParsedArtifact,
): Promise<{ ok: true; keyRaw: Uint8Array } | { ok: false; error: string }> {
  const keyStore = createStagingKeyStore();

  try {
    await keyStore.refresh();
  } catch (e) {
    return {
      ok: false,
      error: `key store refresh failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  const { kid, sig } = artifact.signature;

  if (await keyStore.isKidRevoked(kid)) {
    return { ok: false, error: `signing key revoked: kid=${kid}` };
  }

  const keyRaw = await keyStore.getPublicKeyByKid(kid);
  if (!keyRaw) {
    return { ok: false, error: `unknown signing key: kid=${kid}` };
  }

  // Preimage: artifact with signature.sig absent.
  // signature.alg and signature.kid must be present — AuthorizationV1 contract.
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
    return { ok: false, error: "Ed25519 signature verification failed" };
  }

  return { ok: true, keyRaw };
}

// ─── Main live authorize ──────────────────────────────────────────────────────

/**
 * Full live authorization path for any decision:
 *   1. Compute intent_hash + state_hash locally
 *   2. POST to Sift staging with requested decision + policy
 *   3. Parse response shape (unwrap from "authorization" envelope)
 *   4. Verify Ed25519 signature via real JWKS/KRL
 *   5. Verify hash binding (response hashes match local computation)
 *   6. Return verified result; populate allowArtifact only if decision=ALLOW
 *
 * Fails closed: any step failure returns { ok: false }.
 * The allowArtifact (when present) is NOT execution authorization — it must
 * still pass pepVerify() before anything executes.
 */
export async function liveAuthorize(
  intent: OxDeAIIntent,
  state: NormalizedState,
  decision: string,
  policyId: string,
  audience: string = STAGING_AUDIENCE,
): Promise<LiveAuthorizeResult> {
  // 1. Build request with precomputed hashes
  const body = buildAuthorizeRequestBody(intent, state, decision, policyId, audience);

  // 2. Network call to Sift staging
  const callResult = await callStagingAuthorize(body);
  if (!callResult.ok) return { ok: false, error: callResult.error };

  // 3. Shape validation (unwraps "authorization" envelope)
  const parsed = parseArtifact(callResult.raw);
  if ("error" in parsed) {
    return { ok: false, error: `malformed response: ${parsed.error}` };
  }

  // 4. JWKS/KRL + Ed25519 signature verification
  const verifyResult = await verifyWithKeyStore(parsed);
  if (!verifyResult.ok) return { ok: false, error: verifyResult.error };

  // 5. Hash binding — proves Sift signed over the intent/state we sent
  if (parsed.intent_hash !== body.intent_hash) {
    return {
      ok: false,
      error: `intent_hash mismatch: local=${body.intent_hash} remote=${parsed.intent_hash}`,
    };
  }
  if (parsed.state_hash !== body.state_hash) {
    return {
      ok: false,
      error: `state_hash mismatch: local=${body.state_hash} remote=${parsed.state_hash}`,
    };
  }

  // 6. Return verified result; allowArtifact only when ALLOW
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
    decision: parsed.decision,
    auth_id:  parsed.auth_id,
    policy_id: parsed.policy_id,
    issuer:   parsed.issuer,
    signingKeyRaw: verifyResult.keyRaw,
    allowArtifact,
  };
}
