// SPDX-License-Identifier: Apache-2.0
/**
 * Delegation path tests for @oxdeai/guard.
 *
 * Covers the guard(action, execute, { delegation: { delegation, parentAuth } })
 * execution path introduced in v2.x.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  PolicyEngine,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig, GuardDelegationInput } from "../types.js";

// ── Test key material ─────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

// Delegation is signed by the delegating principal (parentAuth.audience = "agent-A")
const KEYSET: KeySet = {
  issuer: "agent-A",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

const NOW_S = 1_700_000_000;

function makeParentAuth(overrides?: { expiry?: number; audience?: string }): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "pdp-A",
      audience: overrides?.audience ?? "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: NOW_S - 60,
      expiry: overrides?.expiry ?? NOW_S + 3600,
      kid: "k1",
    },
    KEYS.privateKey
  );
}

function makeDelegation(
  parentAuth: AuthorizationV1,
  overrides?: Partial<{ delegatee: string; expiry: number; tools: string[]; max_amount: bigint }>
): DelegationV1 {
  return createDelegation(
    parentAuth,
    {
      delegatee: overrides?.delegatee ?? "agent-B",
      scope: {
        tools: overrides?.tools,
        max_amount: overrides?.max_amount,
      },
      expiry: overrides?.expiry ?? NOW_S + 1800,
      kid: "k1",
    },
    KEYS.privateKey
  );
}

function makeGuardConfig(overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "test-secret-must-be-at-least-32-chars!!" }),
    getState: () => state,
    setState: () => {},
    ...overrides,
  };
}

const baseAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: {
    agent_id: "agent-B",
    target: "gpu-pool",
  },
  timestampSeconds: NOW_S,
};

// ── Happy path ────────────────────────────────────────────────────────────────

test("delegation: valid delegation allows execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig({ trustedKeySets: KEYSET, requireDelegationSignatureVerification: true });
  const guard = OxDeAIGuard(config);

  let executed = false;
  const result = await guard(
    baseAction,
    async () => { executed = true; return "ok"; },
    { delegation: { delegation, parentAuth } }
  );

  assert.ok(executed, "execute should be called on valid delegation");
  assert.equal(result, "ok");
});

test("delegation: does not call setState", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  let setStateCalled = false;

  const config = makeGuardConfig({ setState: () => { setStateCalled = true; } });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth } });

  assert.ok(!setStateCalled, "setState must not be called on delegation path");
});

test("delegation: fires onDecision ALLOW hook with delegation field", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let capturedDecision: string | undefined;
  let capturedDelegation: DelegationV1 | undefined;

  const config = makeGuardConfig({
    onDecision({ decision, delegation: d }) {
      capturedDecision = decision;
      capturedDelegation = d;
    },
  });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth } });

  assert.equal(capturedDecision, "ALLOW");
  assert.ok(capturedDelegation !== undefined, "delegation should be in onDecision record");
  assert.equal(capturedDelegation!.delegation_id, delegation.delegation_id);
});

test("delegation: calls beforeExecute hook", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  const callOrder: string[] = [];
  const config = makeGuardConfig({
    beforeExecute: () => { callOrder.push("beforeExecute"); },
  });
  const guard = OxDeAIGuard(config);

  await guard(
    baseAction,
    async () => { callOrder.push("execute"); },
    { delegation: { delegation, parentAuth } }
  );

  assert.deepEqual(callOrder, ["beforeExecute", "execute"]);
});

// ── Scope enforcement ─────────────────────────────────────────────────────────

test("delegation: blocks action not in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["query_db"] }); // not provision_gpu

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError, `expected OxDeAIDelegationError, got ${err}`);
      assert.ok(err.violations.some((v) => v.includes("provision_gpu")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: allows action in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["provision_gpu", "query_db"] });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  let executed = false;
  await guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth } });
  assert.ok(executed);
});

test("delegation: blocks intent amount exceeding scope.max_amount", async () => {
  const parentAuth = makeParentAuth();
  // max_amount = 0n, action estimatedCost = 1.0 → amount = 1_000_000n
  const delegation = makeDelegation(parentAuth, { max_amount: 0n });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  const expensiveAction: ProposedAction = { ...baseAction, estimatedCost: 1.0 };

  await assert.rejects(
    () => guard(expensiveAction, async () => { executed = true; }, { delegation: { delegation, parentAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.includes("max_amount")));
      return true;
    }
  );
  assert.ok(!executed);
});

// ── Chain verification failures ───────────────────────────────────────────────

test("delegation: blocks expired delegation", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: NOW_S - 1 }); // already expired

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.toLowerCase().includes("expir")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when parent hash mismatches", async () => {
  const parentAuth = makeParentAuth();
  const otherAuth = makeParentAuth({ audience: "agent-X" });
  const delegation = makeDelegation(parentAuth); // bound to parentAuth

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  // Present with the wrong parent
  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth: otherAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks invalid signature when requireDelegationSignatureVerification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const tampered = { ...delegation, delegatee: "agent-EVIL" }; // breaks signature

  const config = makeGuardConfig({
    trustedKeySets: KEYSET,
    requireDelegationSignatureVerification: true,
  });
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation: tampered, parentAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when delegation and parentAuth are missing from input", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, {
      delegation: { delegation: null as unknown as DelegationV1, parentAuth: null as unknown as AuthorizationV1 }
    }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      return true;
    }
  );
});

// ── OxDeAIDelegationError is-a OxDeAIAuthorizationError ───────────────────────

test("OxDeAIDelegationError is instanceof OxDeAIAuthorizationError", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: NOW_S - 1 });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, { delegation: { delegation, parentAuth } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, "OxDeAIDelegationError must be catchable as OxDeAIAuthorizationError");
      assert.ok(err instanceof OxDeAIDelegationError, "and also as OxDeAIDelegationError");
      assert.ok(Array.isArray((err as OxDeAIDelegationError).violations));
      return true;
    }
  );
});

// ── Standard path unaffected ──────────────────────────────────────────────────

test("standard path: unaffected when no opts.delegation provided", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  const result = await guard(baseAction, async () => "standard-ok");
  assert.equal(result, "standard-ok");
});
