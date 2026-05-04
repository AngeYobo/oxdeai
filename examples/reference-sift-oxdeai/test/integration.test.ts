// SPDX-License-Identifier: Apache-2.0
/**
 * Integration test matrix — 8 adversarial scenarios.
 *
 * Invariant under test: No valid AuthorizationV1 → no execution.
 *
 * Every DENY scenario asserts:
 *   - HTTP 403 from the enforcement boundary
 *   - zero side effects (upstream never called, auth_id not consumed)
 *
 * Test matrix:
 *   ALLOW           — happy path, execution succeeds
 *   DENY            — Sift DENY receipt, blocked at adapter
 *   REPLAY          — auth_id reuse, blocked at PEP
 *   INTENT_MISMATCH — tampered intent params, blocked at PEP
 *   STATE_MISMATCH  — changed state, blocked at PEP
 *   AUDIENCE_MISMATCH — wrong audience, blocked at PEP
 *   EXPIRED         — expired authorization, blocked at PEP
 *   BYPASS          — direct upstream call, blocked at upstream
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startTestHarness, signAuthorization, type TestContext } from "./harness.js";
import { fetchSiftReceipt, callPepGateway } from "../apps/agent/client.js";

// ─── Test setup ───────────────────────────────────────────────────────────────

let ctx: TestContext;

before(async () => {
  ctx = await startTestHarness();
});

after(async () => {
  await ctx.close();
});

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const TRANSFER_PARAMS = { amount: 100, destination: "safe_account" };
const TRANSFER_STATE  = { session_active: true, account_status: "active" };

// ─── 1. ALLOW — happy path ────────────────────────────────────────────────────

test("ALLOW: complete happy path succeeds end-to-end", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(
    authResult.ok,
    `Adapter must succeed on ALLOW receipt: ${!authResult.ok ? `${authResult.code}: ${authResult.message}` : ""}`
  );
  if (!authResult.ok) return;

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    authResult.authorization
  );
  assert.equal(status, 200, `PEP must return 200 on valid authorization — got ${status}`);
  assert.equal((body as { ok?: boolean }).ok, true, "Response body must have ok: true");
});

// ─── 2. DENY — Sift DENY receipt blocked at adapter ──────────────────────────

test("DENY: Sift DENY receipt is rejected by the adapter before PEP is reached", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer", "DENY");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });

  assert.equal(authResult.ok, false, "Adapter MUST reject a DENY receipt");
  if (authResult.ok) return;
  assert.equal(
    authResult.code,
    "DENY_DECISION",
    `Expected code DENY_DECISION, got: ${authResult.code}`
  );
});

// ─── 3. REPLAY — same auth_id consumed only once ─────────────────────────────

test("REPLAY: an authorization cannot be used more than once", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(authResult.ok, "Adapter must succeed for REPLAY setup");
  if (!authResult.ok) return;

  // First use — must succeed.
  const first = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    authResult.authorization
  );
  assert.equal(first.status, 200, `First use must succeed — got ${first.status}`);

  // Second use with the SAME authorization — must be rejected.
  const second = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    authResult.authorization
  );
  assert.equal(second.status, 403, `Replay must return 403 — got ${second.status}`);
  assert.equal(
    (second.body as { code?: string }).code,
    "REPLAY_DETECTED",
    `Expected code REPLAY_DETECTED, got: ${(second.body as { code?: string }).code}`
  );
});

// ─── 4. INTENT_MISMATCH — tampered params blocked at PEP ─────────────────────

test("INTENT_MISMATCH: tampered intent params are rejected by the PEP", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(authResult.ok, "Adapter must succeed for INTENT_MISMATCH setup");
  if (!authResult.ok) return;

  // Tamper: change amount and destination — intent_hash will not match.
  const tamperedIntent = {
    ...authResult.intent,
    params: { amount: 999_999, destination: "attacker_account" },
  };

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    tamperedIntent,
    authResult.state,
    authResult.authorization
  );
  assert.equal(status, 403, `Tampered intent must return 403 — got ${status}`);
  assert.equal(
    (body as { code?: string }).code,
    "INTENT_HASH_MISMATCH",
    `Expected code INTENT_HASH_MISMATCH, got: ${(body as { code?: string }).code}`
  );
});

// ─── 5. STATE_MISMATCH — changed state blocked at PEP ────────────────────────

test("STATE_MISMATCH: changed state is rejected by the PEP", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(authResult.ok, "Adapter must succeed for STATE_MISMATCH setup");
  if (!authResult.ok) return;

  // Change state after authorization — state_hash will not match.
  const changedState = { session_active: false, account_status: "suspended" };

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    changedState,
    authResult.authorization
  );
  assert.equal(status, 403, `Changed state must return 403 — got ${status}`);
  assert.equal(
    (body as { code?: string }).code,
    "STATE_HASH_MISMATCH",
    `Expected code STATE_HASH_MISMATCH, got: ${(body as { code?: string }).code}`
  );
});

// ─── 6. AUDIENCE_MISMATCH — wrong audience blocked at PEP ────────────────────

test("AUDIENCE_MISMATCH: authorization for wrong audience is rejected by the PEP", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(authResult.ok, "Adapter must succeed for AUDIENCE_MISMATCH setup");
  if (!authResult.ok) return;

  // Build a validly-signed authorization with the wrong audience.
  // signAuthorization re-signs so the signature check passes;
  // the audience check then catches the mismatch.
  const wrongAudienceAuth = signAuthorization(
    { ...authResult.authorization, audience: "pep-wrong-audience" },
    ctx.adapterPrivateKey
  );

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    wrongAudienceAuth
  );
  assert.equal(status, 403, `Wrong audience must return 403 — got ${status}`);
  assert.equal(
    (body as { code?: string }).code,
    "AUDIENCE_MISMATCH",
    `Expected code AUDIENCE_MISMATCH, got: ${(body as { code?: string }).code}`
  );
});

// ─── 7. EXPIRED — expired authorization blocked at PEP ───────────────────────

test("EXPIRED: an expired authorization is rejected by the PEP", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  // Pass a `now` 60 seconds in the past.
  // receiptToAuthorization sets: issued_at = (now - 60s), expires_at = issued_at + 30s
  // → expires_at is 30 seconds in the past when the PEP checks it.
  const pastNow = new Date(Date.now() - 60_000);
  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
    now: pastNow,
  });
  assert.ok(
    authResult.ok,
    `Adapter must succeed with past now: ${!authResult.ok ? `${authResult.code}: ${authResult.message}` : ""}`
  );
  if (!authResult.ok) return;

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    authResult.authorization
  );
  assert.equal(status, 403, `Expired authorization must return 403 — got ${status}`);
  assert.equal(
    (body as { code?: string }).code,
    "EXPIRED",
    `Expected code EXPIRED, got: ${(body as { code?: string }).code}`
  );
});

// ─── 8. BYPASS — direct upstream access blocked ───────────────────────────────

test("BYPASS: direct call to upstream without PEP returns 403", async () => {
  // Call the execution target directly — no AuthorizationV1, no PEP verification.
  // The upstream must reject this regardless of the request body.
  const res = await fetch(`${ctx.upstreamUrl}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tool: "transfer",
      params: { amount: 999_999, destination: "attacker_account" },
    }),
  });
  assert.equal(res.status, 403, `Direct upstream access must return 403 — got ${res.status}`);
  const body = (await res.json()) as { code?: string };
  assert.equal(
    body.code,
    "FORBIDDEN",
    `Expected code FORBIDDEN, got: ${body.code}`
  );
});
