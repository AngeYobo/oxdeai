// SPDX-License-Identifier: Apache-2.0
/**
 * Live staging integration test for examples/sift.
 *
 * GATED: only runs when SIFT_STAGING_LIVE=1 is set.
 * Without the flag the test reports as skipped — no network calls are made.
 *
 * Run:
 *   pnpm -C examples/sift test:staging
 *
 * What this proves:
 *   - the live staging authorize endpoint is reachable and returns ALLOW
 *   - the response signature verifies against the real JWKS/KRL
 *   - the OxDeAI PEP enforces the artifact on the first pass (executed: true)
 *   - the OxDeAI PEP denies replay on the second pass (reason: REPLAY)
 *
 * What is NOT covered here (covered by packages/sift tests):
 *   - canonicalization byte-parity
 *   - DENY / REPLAY decision handling
 *   - JWKS/KRL parse edge cases
 *   - PEP conformance vectors
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeState } from "@oxdeai/sift";
import type { OxDeAIIntent } from "@oxdeai/sift";
import { pepVerify } from "./helpers.js";
import { liveAuthorize, STAGING_AUDIENCE } from "./liveStaging.js";

// ─── Environment gate ─────────────────────────────────────────────────────────

const LIVE = process.env["SIFT_STAGING_LIVE"] === "1";
const skip = LIVE ? undefined : "set SIFT_STAGING_LIVE=1 to run live staging tests";

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const testIntent: OxDeAIIntent = {
  type: "EXECUTE",
  tool: "read_file",
  params: { path: "/etc/hostname", mode: "ro" },
};

// ─── Test ─────────────────────────────────────────────────────────────────────

test(
  "live ALLOW → local verify → PEP allows → PEP denies replay",
  { skip },
  async () => {
    const stateResult = normalizeState({
      state: { agent: "oxdeai-staging-test", session_active: true },
      requiredKeys: [],
    });
    if (!stateResult.ok) assert.fail(`state normalization failed: ${stateResult.code}`);
    const testState = stateResult.state;

    // ── 1. Live authorize call + JWKS/KRL verification ──────────────────────
    const result = await liveAuthorize(
      testIntent, testState, "ALLOW", "read-only-low-risk", STAGING_AUDIENCE
    );

    if (!result.ok) assert.fail(`live authorize failed: ${result.error}`);

    assert.equal(result.decision, "ALLOW", "Sift decision must be ALLOW");
    assert.ok(result.allowArtifact !== null, "allowArtifact must be populated for ALLOW");

    if (result.allowArtifact === null) return; // TypeScript narrowing
    const artifact   = result.allowArtifact;
    const pepIssuerKey = Buffer.from(result.signingKeyRaw);

    assert.equal(artifact.version,  "AuthorizationV1");
    assert.equal(artifact.issuer,   "sift-staging.walkosystems.com");
    assert.equal(artifact.audience, STAGING_AUDIENCE);
    assert.equal(artifact.decision, "ALLOW");
    assert.ok(artifact.auth_id.length > 0,   "auth_id must be non-empty");
    assert.ok(artifact.signature.sig.length > 0, "signature.sig must be non-empty");

    // ── 2. PEP enforcement — first pass ─────────────────────────────────────
    const pep1 = pepVerify({
      authorization: artifact,
      intent: testIntent,
      state: testState,
      audience: STAGING_AUDIENCE,
      issuerPublicKeyRaw: pepIssuerKey,
      now: new Date(),
    });

    if (!pep1.ok) assert.fail(`PEP denied first execution: ${pep1.reason}`);
    assert.equal(pep1.decision, "ALLOW");
    assert.equal(pep1.executed, true);

    // ── 3. PEP enforcement — replay must be denied ──────────────────────────
    const pep2 = pepVerify({
      authorization: artifact,
      intent: testIntent,
      state: testState,
      audience: STAGING_AUDIENCE,
      issuerPublicKeyRaw: pepIssuerKey,
      now: new Date(),
    });

    if (pep2.ok) assert.fail("PEP should have denied replay attempt");
    assert.equal(pep2.decision, "DENY");
    assert.equal(pep2.reason,   "REPLAY");
    assert.equal(pep2.executed, false);
  }
);
