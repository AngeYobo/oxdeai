import type { Intent, PolicyEngine, State, Authorization } from "@oxdeai/core";
import type { AuditAdapter, ClockAdapter, MaybePromise, StateAdapter, IntentBuilderInput } from "./types.js";
import { buildIntent } from "./builders.js";

export type GuardDecision =
  | { decision: "ALLOW"; reasons: []; authorization: Authorization }
  | { decision: "DENY"; reasons: string[] };

export type GuardAllowResult<T> = {
  output: GuardDecision & { decision: "ALLOW"; reasons: []; authorization: Authorization };
  intent: Intent;
  state: State;
  auditEvents: unknown[];
  executed: true;
  executionResult: T;
};

export type GuardDenyResult = {
  output: GuardDecision & { decision: "DENY"; reasons: string[] };
  intent: Intent;
  state: State;
  auditEvents: unknown[];
  executed: false;
};

export type GuardResult<T> = GuardAllowResult<T> | GuardDenyResult;

export type GuardInputIntent = Intent | IntentBuilderInput;

export type GuardOptions = {
  engine: PolicyEngine;
  stateAdapter: StateAdapter;
  auditAdapter?: AuditAdapter;
  clock?: ClockAdapter;
  mode?: "fail-fast" | "collect-all";
  verifyAuthorization?: boolean;
};

type GuardExecuteContext = {
  intent: Intent;
  authorization: Authorization;
  state: State;
};

function collectNewEvents(engine: PolicyEngine, cursor: number): { nextCursor: number; events: unknown[] } {
  const all = engine.audit.snapshot() as unknown[];
  return { nextCursor: all.length, events: all.slice(cursor) };
}

function isIntent(value: GuardInputIntent): value is Intent {
  return (
    typeof (value as Intent).intent_id === "string" &&
    typeof (value as Intent).agent_id === "string" &&
    typeof (value as Intent).action_type === "string" &&
    typeof (value as Intent).signature === "string"
  );
}

export type GuardFn = <T>(
  input: GuardInputIntent,
  execute: (ctx: GuardExecuteContext) => MaybePromise<T>
) => Promise<GuardResult<T>>;

export function createGuard(opts: GuardOptions): GuardFn {
  const clock = opts.clock ?? { now: () => Math.floor(Date.now() / 1000) };
  let auditCursor = 0;

  return async function guard<T>(
    input: GuardInputIntent,
    execute: (ctx: GuardExecuteContext) => MaybePromise<T>
  ): Promise<GuardResult<T>> {
    const state = await opts.stateAdapter.load();
    const intent: Intent = isIntent(input)
      ? ({
          ...input,
          timestamp: input.timestamp === 0 ? clock.now() : input.timestamp,
        } as Intent)
      : buildIntent({
          ...input,
          timestamp: input.timestamp ?? clock.now(),
        });

    const out = opts.engine.evaluatePure(intent, state, { mode: opts.mode ?? "fail-fast" });
    const emitted = collectNewEvents(opts.engine, auditCursor);
    auditCursor = emitted.nextCursor;

    if (opts.auditAdapter) await opts.auditAdapter.append(emitted.events);

    if (out.decision === "DENY") {
      return {
        output: { decision: "DENY", reasons: out.reasons },
        intent,
        state,
        auditEvents: emitted.events,
        executed: false,
      };
    }

    if (!out.authorization || !out.nextState) {
      return {
        output: { decision: "DENY", reasons: ["PEP_INVARIANT_VIOLATION"] },
        intent,
        state,
        auditEvents: emitted.events,
        executed: false,
      };
    }

    if (opts.verifyAuthorization !== false) {
      const authCheck = opts.engine.verifyAuthorization(intent, out.authorization, out.nextState, intent.timestamp);
      if (!authCheck.valid) {
        return {
          output: { decision: "DENY", reasons: [`AUTH_INVALID:${authCheck.reason ?? "unknown"}`] },
          intent,
          state,
          auditEvents: emitted.events,
          executed: false,
        };
      }
    }

    const executionResult = await execute({
      intent,
      authorization: out.authorization,
      state: out.nextState,
    });
    await opts.stateAdapter.save(out.nextState);

    return {
      output: { decision: "ALLOW", reasons: [], authorization: out.authorization },
      intent,
      state: out.nextState,
      auditEvents: emitted.events,
      executed: true,
      executionResult,
    };
  };
}
