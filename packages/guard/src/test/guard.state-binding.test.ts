// SPDX-License-Identifier: Apache-2.0
/**
 * guard.state-binding.test.ts
 *
 * Verifies that OxDeAIGuard enforces state_hash binding at the PEP boundary:
 * the authorization's state_hash must equal stateSnapshotHash(executionState).
 *
 * Test IDs: SB-1 through SB-8.
 *
 *   SB-1  Matching state_hash         → execute runs, result returned
 *   SB-2  Mismatched state_hash       → OxDeAIAuthorizationError, execute blocked
 *   SB-3  Empty/missing state_hash    → OxDeAIAuthorizationError, execute blocked
 *   SB-4  Uncanonicalizeable state    → OxDeAIAuthorizationError, execute blocked
 *   SB-5  Determinism                 → same state always produces the same hash
 *   SB-6  TOCTOU state mutation       → state mutated after auth issued → execute blocked
 *   SB-7  Null execution state        → computeStateHash throws → execute blocked
 *   SB-8  Boundary integrity          → mismatch blocks beforeExecute, execute, and setState
 */

import test from "node:test";
import assert from "node:assert/strict";

import type { Authorization, Intent, State } from "@oxdeai/core";
import { stateSnapshotHash } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import { TEST_KEYSET, signAuth } from "./helpers/fixtures.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

// ── shared fixtures ────────────────────────────────────────────────────────────

const ACTION: ProposedAction = {
  name: "transfer",
  args: { amount: 100 },
  estimatedCost: 0,
  context: { agent_id: "agent-sb" },
};

function makeBaseState(): State {
  return {
    policy_version: "sb-policy",
    period_id: "sb-p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-sb": 1_000_000n },
      spent_in_period: { "agent-sb": 0n },
    },
    max_amount_per_action: { "agent-sb": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-sb": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-sb": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-sb": 100 }, calls: {} },
  };
}

function makeFakeEngine(auth: ReturnType<typeof signAuth>, _state: State) {
  return {
    evaluatePure(_intent: Intent, s: State) {
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState: s,
      };
    },
    computeStateHash: (s: State) => stateSnapshotHash(s),
  };
}

function makeGuardConfig(
  auth: ReturnType<typeof signAuth>,
  state: State,
  overrides?: Partial<OxDeAIGuardConfig>
): OxDeAIGuardConfig {
  let stored = state;
  return {
    engine: makeFakeEngine(auth, state) as any,
    getState: async () => stored,
    setState: async (s) => { stored = s; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

// ── SB-1: Matching state_hash → execute runs ───────────────────────────────────

test("SB-1 matching state_hash: execute runs and result is returned", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "sb1-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;
  const result = await guard(ACTION, async () => { executed = true; return "sb1-ok"; });

  assert.ok(executed, "execute must be called when state_hash matches");
  assert.equal(result, "sb1-ok");
});

// ── SB-2: Mismatched state_hash → execute blocked ─────────────────────────────

test("SB-2 mismatched state_hash: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  // Auth commits to a different state (wrong hash).
  const wrongHash = "a".repeat(64);
  const auth = signAuth({
    auth_id: "sb2-auth",
    audience: "aud-test",
    state_hash: wrongHash,
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      assert.ok(
        err.message.includes("state_hash"),
        `error message should mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state_hash does not match");
});

// ── SB-3: Empty state_hash → execute blocked ──────────────────────────────────

test("SB-3 empty state_hash in authorization: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  // signAuth defaults state_hash to "s".repeat(64); override to empty string.
  // verifyAuthorization (strict) rejects empty state_hash before state binding.
  const auth = signAuth({
    auth_id: "sb3-auth",
    audience: "aud-test",
    state_hash: "",
  });

  const guard = OxDeAIGuard(makeGuardConfig(auth, state));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state_hash is empty");
});

// ── SB-4: Uncanonicalizeable state → execute blocked ──────────────────────────

test("SB-4 state that cannot be canonicalized: execute is blocked and OxDeAIAuthorizationError is thrown", async () => {
  const state = makeBaseState();
  const auth = signAuth({
    auth_id: "sb4-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(state),
  });

  // Introduce a circular reference so JSON.stringify throws inside stateSnapshotHash.
  const circularState = { ...state } as any;
  circularState._self = circularState;

  const guard = OxDeAIGuard(makeGuardConfig(auth, circularState));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`);
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("state_hash"),
        `error message should indicate canonicalization or state_hash failure, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state cannot be canonicalized");
});

// ── SB-5: Determinism — same state always produces the same hash ───────────────

test("SB-5 determinism: stateSnapshotHash is stable and three guard runs with the same state all ALLOW", async () => {
  const state = makeBaseState();

  // Hash stability: repeated calls on the same state object return the same value.
  const h1 = stateSnapshotHash(state);
  const h2 = stateSnapshotHash(state);
  const h3 = stateSnapshotHash(state);
  assert.equal(h1, h2, "stateSnapshotHash must be idempotent (call 1 vs 2)");
  assert.equal(h2, h3, "stateSnapshotHash must be idempotent (call 2 vs 3)");

  // Structural equivalence: two independent makeBaseState() calls hash the same.
  const state2 = makeBaseState();
  assert.equal(
    stateSnapshotHash(state),
    stateSnapshotHash(state2),
    "two independent makeBaseState() objects must hash identically"
  );

  // structuredClone stability: a deep clone produces the same hash.
  const cloned = structuredClone(state);
  assert.equal(
    stateSnapshotHash(state),
    stateSnapshotHash(cloned),
    "structuredClone of state must hash identically to the original"
  );

  // Three independent guard runs, each with a distinct auth_id but the same
  // state_hash commitment, all produce ALLOW.
  const sharedHash = stateSnapshotHash(state);
  for (const [idx, authId] of (["sb5-run-a", "sb5-run-b", "sb5-run-c"] as const).entries()) {
    const auth = signAuth({ auth_id: authId, audience: "aud-test", state_hash: sharedHash });
    const guard = OxDeAIGuard(makeGuardConfig(auth, makeBaseState()));
    let ran = false;
    const res = await guard(ACTION, async () => { ran = true; return `run-${idx}`; });
    assert.ok(ran, `run ${authId}: execute must be called`);
    assert.equal(res, `run-${idx}`, `run ${authId}: result must be returned`);
  }
});

// ── SB-6: TOCTOU — state mutated after auth was issued → execute blocked ───────

test("SB-6 TOCTOU state mutation: state modified after authorization was issued blocks execution", async () => {
  // Auth was issued against a clean state (spent_in_period: 0n).
  const authState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb6-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(authState),
  });

  // By execution time, state has advanced (a payment was recorded).
  const executionState = makeBaseState();
  executionState.budget.spent_in_period["agent-sb"] = 500_000n;

  // stateSnapshotHash must differ between authState and executionState.
  assert.notEqual(
    stateSnapshotHash(authState),
    stateSnapshotHash(executionState),
    "precondition: authState and executionState must have different hashes"
  );

  const guard = OxDeAIGuard(makeGuardConfig(auth, executionState));
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("state_hash"),
        `error message should mention state_hash, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state was mutated after auth was issued");
});

// ── SB-7: Null execution state → computeStateHash throws → execute blocked ─────

test("SB-7 null execution state: computeStateHash throws and execution is blocked", async () => {
  // Build an auth with a valid, non-empty state_hash so it passes strictVerifyAuthorization.
  const validState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb7-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(validState),
  });

  // Custom engine whose computeStateHash explicitly throws for null/undefined state.
  // evaluatePure returns ALLOW+nextState even when given null so the guard reaches step 6c.
  const nullSafeNextState = makeBaseState();
  const engineWithNullGuard = {
    evaluatePure(_intent: Intent, _s: unknown) {
      return {
        decision: "ALLOW" as const,
        reasons: [],
        authorization: auth as unknown as Authorization,
        nextState: nullSafeNextState,
      };
    },
    computeStateHash(s: unknown): string {
      if (s === null || s === undefined) {
        throw new TypeError("computeStateHash: state is null or undefined");
      }
      return stateSnapshotHash(s as State);
    },
  };

  const config: OxDeAIGuardConfig = {
    engine: engineWithNullGuard as any,
    // getState returns null — simulates a broken/uninitialized state store.
    getState: async () => null as unknown as State,
    setState: async () => {},
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(ACTION, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(
        err instanceof OxDeAIAuthorizationError,
        `expected OxDeAIAuthorizationError, got: ${Object.prototype.toString.call(err)}`
      );
      assert.ok(
        err.message.includes("canonicalization") || err.message.includes("State"),
        `error message should indicate state failure, got: ${err.message}`
      );
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when state is null");
});

// ── SB-8: Boundary integrity — mismatch blocks beforeExecute, execute, setState ─

test("SB-8 boundary integrity: state_hash mismatch blocks beforeExecute, execute, and setState", async () => {
  // Auth commits to a clean state; guard will see a mutated state at execution time.
  const authState = makeBaseState();
  const auth = signAuth({
    auth_id: "sb8-auth",
    audience: "aud-test",
    state_hash: stateSnapshotHash(authState),
  });

  const executionState = makeBaseState();
  executionState.budget.spent_in_period["agent-sb"] = 999_999n;

  let beforeExecuteCalled = false;
  let setStateCalled = false;
  let executeCalled = false;

  const config = makeGuardConfig(auth, executionState, {
    beforeExecute: async () => { beforeExecuteCalled = true; },
    setState: async () => { setStateCalled = true; },
  });

  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(ACTION, async () => { executeCalled = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, "must throw OxDeAIAuthorizationError");
      return true;
    }
  );

  assert.ok(!beforeExecuteCalled, "beforeExecute must not be called when state_hash mismatches");
  assert.ok(!executeCalled, "execute must not be called when state_hash mismatches");
  assert.ok(!setStateCalled, "setState must not be called when state_hash mismatches");
});
