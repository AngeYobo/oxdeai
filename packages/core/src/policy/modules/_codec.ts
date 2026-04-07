// SPDX-License-Identifier: Apache-2.0
import type { ActionType } from "../../types/intent.js";
import type {
  AllowLists,
  ModuleStateCodec,
  State,
  StateHash,
  ToolLimitsState,
  VelocityCounters
} from "../../types/state.js";
import { sha256HexFromJson } from "../../crypto/hashes.js";

export type StateBoundModuleCodec = ModuleStateCodec;

type JsonObject = Record<string, unknown>;

const DECIMAL_BIGINT = /^(0|[1-9]\d*)$/;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null;
}

function asObject(value: unknown, field: string): JsonObject {
  if (!isObject(value) || Array.isArray(value)) {
    throw new Error(`invalid ${field}`);
  }
  return value;
}

function asStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new Error(`invalid ${field}`);
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") throw new Error(`invalid ${field}`);
    out.push(entry);
  }
  return out;
}

function assertInt(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`invalid ${field}`);
  }
  return value;
}

function assertPosInt(value: unknown, field: string): number {
  const n = assertInt(value, field);
  if (n <= 0) throw new Error(`invalid ${field}`);
  return n;
}

function assertNonNegInt(value: unknown, field: string): number {
  const n = assertInt(value, field);
  if (n < 0) throw new Error(`invalid ${field}`);
  return n;
}

function assertDecimalBigIntString(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !DECIMAL_BIGINT.test(value)) {
    throw new Error(`invalid ${field}`);
  }
  return BigInt(value);
}

function sortedKeys<T>(rec: Record<string, T | undefined>): string[] {
  return Object.keys(rec).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function uniqSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function normalizeAllowlists(allowlists: AllowLists): { action_types: ActionType[]; assets: string[]; targets: string[] } {
  const action_types = uniqSorted((allowlists.action_types ?? []) as string[]) as ActionType[];
  const assets = uniqSorted(allowlists.assets ?? []);
  const targets = uniqSorted(allowlists.targets ?? []);
  return { action_types, assets, targets };
}

function normalizeBudget(state: State): {
  budget_limit: Record<string, string>;
  spent_in_period: Record<string, string>;
  max_amount_per_action: Record<string, string>;
} {
  const budget_limit: Record<string, string> = {};
  for (const agent of sortedKeys(state.budget.budget_limit)) {
    const value = state.budget.budget_limit[agent];
    if (value === undefined) continue;
    budget_limit[agent] = value.toString();
  }

  const spent_in_period: Record<string, string> = {};
  for (const agent of sortedKeys(state.budget.spent_in_period)) {
    const value = state.budget.spent_in_period[agent];
    if (value === undefined) continue;
    spent_in_period[agent] = value.toString();
  }

  const max_amount_per_action: Record<string, string> = {};
  for (const agent of sortedKeys(state.max_amount_per_action)) {
    const value = state.max_amount_per_action[agent];
    if (value === undefined) continue;
    max_amount_per_action[agent] = value.toString();
  }

  return { budget_limit, spent_in_period, max_amount_per_action };
}

function normalizeVelocity(state: State): { config: { window_seconds: number; max_actions: number }; counters: Record<string, { window_start: number; count: number }> } {
  const config = {
    window_seconds: assertPosInt(state.velocity.config.window_seconds, "velocity.config.window_seconds"),
    max_actions: assertNonNegInt(state.velocity.config.max_actions, "velocity.config.max_actions")
  };

  const counters: Record<string, { window_start: number; count: number }> = {};
  for (const agent of sortedKeys(state.velocity.counters)) {
    const counter = state.velocity.counters[agent];
    if (!counter) continue;
    counters[agent] = {
      window_start: assertInt(counter.window_start, "velocity.counters.window_start"),
      count: assertNonNegInt(counter.count, "velocity.counters.count")
    };
  }

  return { config, counters };
}

function normalizeReplay(state: State): {
  window_seconds: number;
  max_nonces_per_agent: number;
  nonces: Record<string, Array<{ nonce: string; ts: number }>>;
} {
  const out: Record<string, Array<{ nonce: string; ts: number }>> = {};

  for (const agent of sortedKeys(state.replay.nonces)) {
    const list = state.replay.nonces[agent] ?? [];
    const normalized = list
      .map((entry) => ({
        nonce: String(entry.nonce),
        ts: assertInt(entry.ts, "replay.nonces.ts")
      }))
      .sort((a, b) => (a.ts - b.ts) || (a.nonce < b.nonce ? -1 : a.nonce > b.nonce ? 1 : 0));

    const seen = new Set<string>();
    for (const entry of normalized) {
      const key = `${entry.ts}:${entry.nonce}`;
      if (seen.has(key)) throw new Error("invalid replay.nonces duplicate");
      seen.add(key);
    }
    out[agent] = normalized;
  }

  return {
    window_seconds: assertPosInt(state.replay.window_seconds, "replay.window_seconds"),
    max_nonces_per_agent: assertNonNegInt(state.replay.max_nonces_per_agent, "replay.max_nonces_per_agent"),
    nonces: out
  };
}

function normalizeConcurrency(state: State): {
  max_concurrent: Record<string, number>;
  active: Record<string, number>;
  active_auths: Record<string, Record<string, { expires_at: number }>>;
} {
  const max_concurrent: Record<string, number> = {};
  const active: Record<string, number> = {};
  const active_auths: Record<string, Record<string, { expires_at: number }>> = {};

  const agents = new Set<string>([
    ...Object.keys(state.concurrency.max_concurrent),
    ...Object.keys(state.concurrency.active),
    ...Object.keys(state.concurrency.active_auths)
  ]);

  for (const agent of [...agents].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
    const max = assertNonNegInt(state.concurrency.max_concurrent[agent] ?? 0, "concurrency.max_concurrent");
    const act = assertNonNegInt(state.concurrency.active[agent] ?? 0, "concurrency.active");
    if (act > max) throw new Error("invalid concurrency.active exceeds max_concurrent");

    max_concurrent[agent] = max;
    active[agent] = act;

    const src = state.concurrency.active_auths[agent] ?? {};
    const dst: Record<string, { expires_at: number }> = {};
    for (const authId of Object.keys(src).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      const item = src[authId];
      dst[authId] = { expires_at: assertInt(item.expires_at, "concurrency.active_auths.expires_at") };
    }
    active_auths[agent] = dst;
  }

  return { max_concurrent, active, active_auths };
}

function normalizeRecursion(state: State): { max_depth: Record<string, number> } {
  const max_depth: Record<string, number> = {};
  for (const agent of sortedKeys(state.recursion.max_depth)) {
    max_depth[agent] = assertNonNegInt(state.recursion.max_depth[agent], "recursion.max_depth");
  }
  return { max_depth };
}

function normalizeToolLimits(state: State): {
  window_seconds: number;
  max_calls: Record<string, number>;
  max_calls_by_tool: Record<string, Record<string, number>>;
  calls: Record<string, Array<{ ts: number; tool?: string }>>;
} {
  const tl: ToolLimitsState = state.tool_limits ?? {
    window_seconds: 0,
    max_calls: {},
    max_calls_by_tool: {},
    calls: {}
  };

  const max_calls: Record<string, number> = {};
  for (const agent of sortedKeys(tl.max_calls)) {
    const v = tl.max_calls[agent];
    if (v === undefined) continue;
    max_calls[agent] = assertNonNegInt(v, "tool_limits.max_calls");
  }

  const max_calls_by_tool: Record<string, Record<string, number>> = {};
  const byTool = tl.max_calls_by_tool ?? {};
  for (const agent of sortedKeys(byTool)) {
    const tools = byTool[agent] ?? {};
    const out: Record<string, number> = {};
    for (const tool of Object.keys(tools).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      const v = tools[tool];
      if (v === undefined) continue;
      out[tool] = assertNonNegInt(v, "tool_limits.max_calls_by_tool");
    }
    max_calls_by_tool[agent] = out;
  }

  const calls: Record<string, Array<{ ts: number; tool?: string }>> = {};
  for (const agent of sortedKeys(tl.calls)) {
    const entries = tl.calls[agent] ?? [];
    calls[agent] = entries
      .map((e) => ({
        ts: assertInt(e.ts, "tool_limits.calls.ts"),
        tool: e.tool
      }))
      .sort((a, b) => (a.ts - b.ts) || ((a.tool ?? "") < (b.tool ?? "") ? -1 : (a.tool ?? "") > (b.tool ?? "") ? 1 : 0));
  }

  return {
    window_seconds: assertPosInt(tl.window_seconds, "tool_limits.window_seconds"),
    max_calls,
    max_calls_by_tool,
    calls
  };
}

function hashPayload(payload: unknown): StateHash {
  return sha256HexFromJson(payload);
}

export const MODULE_CODECS: Record<string, StateBoundModuleCodec> = {
  AllowlistModule: {
    moduleId: "AllowlistModule",
    serializeState(state: State): unknown {
      return normalizeAllowlists(state.allowlists);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.allowlists = {};
        return;
      }
      const obj = asObject(payload, "allowlists");
      const normalized = normalizeAllowlists({
        action_types: obj.action_types === undefined ? [] : (asStringArray(obj.action_types, "allowlists.action_types") as ActionType[]),
        assets: obj.assets === undefined ? [] : asStringArray(obj.assets, "allowlists.assets"),
        targets: obj.targets === undefined ? [] : asStringArray(obj.targets, "allowlists.targets")
      });
      state.allowlists = normalized;
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  BudgetModule: {
    moduleId: "BudgetModule",
    serializeState(state: State): unknown {
      return normalizeBudget(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.budget = { budget_limit: {}, spent_in_period: {} };
        state.max_amount_per_action = {};
        return;
      }
      const obj = asObject(payload, "budget");
      const budgetLimitObj = asObject(obj.budget_limit ?? {}, "budget.budget_limit");
      const spentObj = asObject(obj.spent_in_period ?? {}, "budget.spent_in_period");
      const capObj = asObject(obj.max_amount_per_action ?? {}, "budget.max_amount_per_action");

      const budget_limit: Record<string, bigint> = {};
      for (const agent of Object.keys(budgetLimitObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        budget_limit[agent] = assertDecimalBigIntString(budgetLimitObj[agent], `budget_limit.${agent}`);
      }

      const spent_in_period: Record<string, bigint> = {};
      for (const agent of Object.keys(spentObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        spent_in_period[agent] = assertDecimalBigIntString(spentObj[agent], `spent_in_period.${agent}`);
      }

      const max_amount_per_action: Record<string, bigint> = {};
      for (const agent of Object.keys(capObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        max_amount_per_action[agent] = assertDecimalBigIntString(capObj[agent], `max_amount_per_action.${agent}`);
      }

      state.budget = { budget_limit, spent_in_period };
      state.max_amount_per_action = max_amount_per_action;
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  VelocityModule: {
    moduleId: "VelocityModule",
    serializeState(state: State): unknown {
      return normalizeVelocity(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.velocity = { config: { window_seconds: 1, max_actions: 0 }, counters: {} };
        return;
      }
      const obj = asObject(payload, "velocity");
      const config = asObject(obj.config, "velocity.config");
      const countersObj = asObject(obj.counters ?? {}, "velocity.counters");

      const counters: VelocityCounters = {};
      for (const agent of Object.keys(countersObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        const item = asObject(countersObj[agent], `velocity.counters.${agent}`);
        counters[agent] = {
          window_start: assertInt(item.window_start, `velocity.counters.${agent}.window_start`),
          count: assertNonNegInt(item.count, `velocity.counters.${agent}.count`)
        };
      }

      state.velocity = {
        config: {
          window_seconds: assertPosInt(config.window_seconds, "velocity.config.window_seconds"),
          max_actions: assertNonNegInt(config.max_actions, "velocity.config.max_actions")
        },
        counters
      };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  ReplayModule: {
    moduleId: "ReplayModule",
    serializeState(state: State): unknown {
      return normalizeReplay(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.replay = { window_seconds: 1, max_nonces_per_agent: 0, nonces: {} };
        return;
      }
      const obj = asObject(payload, "replay");
      const noncesObj = asObject(obj.nonces ?? {}, "replay.nonces");
      const nonces: Record<string, Array<{ nonce: string; ts: number }>> = {};

      for (const agent of Object.keys(noncesObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        const entries = noncesObj[agent];
        if (!Array.isArray(entries)) throw new Error(`invalid replay.nonces.${agent}`);
        const normalized = entries
          .map((entry, index) => {
            const e = asObject(entry, `replay.nonces.${agent}[${index}]`);
            const nonce = e.nonce;
            if (typeof nonce !== "string") throw new Error(`invalid replay.nonces.${agent}[${index}].nonce`);
            return { nonce, ts: assertInt(e.ts, `replay.nonces.${agent}[${index}].ts`) };
          })
          .sort((a, b) => (a.ts - b.ts) || (a.nonce < b.nonce ? -1 : a.nonce > b.nonce ? 1 : 0));

        const seen = new Set<string>();
        for (const entry of normalized) {
          const key = `${entry.ts}:${entry.nonce}`;
          if (seen.has(key)) throw new Error(`invalid replay.nonces.${agent} duplicate`);
          seen.add(key);
        }
        nonces[agent] = normalized;
      }

      state.replay = {
        window_seconds: assertPosInt(obj.window_seconds, "replay.window_seconds"),
        max_nonces_per_agent: assertNonNegInt(obj.max_nonces_per_agent, "replay.max_nonces_per_agent"),
        nonces
      };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  ConcurrencyModule: {
    moduleId: "ConcurrencyModule",
    serializeState(state: State): unknown {
      return normalizeConcurrency(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.concurrency = { max_concurrent: {}, active: {}, active_auths: {} };
        return;
      }
      const obj = asObject(payload, "concurrency");
      const maxObj = asObject(obj.max_concurrent ?? {}, "concurrency.max_concurrent");
      const activeObj = asObject(obj.active ?? {}, "concurrency.active");
      const authsObj = asObject(obj.active_auths ?? {}, "concurrency.active_auths");

      const max_concurrent: Record<string, number> = {};
      const active: Record<string, number> = {};
      const active_auths: Record<string, Record<string, { expires_at: number }>> = {};

      const agents = new Set<string>([
        ...Object.keys(maxObj),
        ...Object.keys(activeObj),
        ...Object.keys(authsObj)
      ]);

      for (const agent of [...agents].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        const max = assertNonNegInt(maxObj[agent] ?? 0, `concurrency.max_concurrent.${agent}`);
        const act = assertNonNegInt(activeObj[agent] ?? 0, `concurrency.active.${agent}`);
        if (act > max) throw new Error(`invalid concurrency.active.${agent}`);

        max_concurrent[agent] = max;
        active[agent] = act;

        const agentAuthsRaw = asObject(authsObj[agent] ?? {}, `concurrency.active_auths.${agent}`);
        const agentAuths: Record<string, { expires_at: number }> = {};
        for (const authId of Object.keys(agentAuthsRaw).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
          const authPayload = asObject(agentAuthsRaw[authId], `concurrency.active_auths.${agent}.${authId}`);
          agentAuths[authId] = {
            expires_at: assertInt(authPayload.expires_at, `concurrency.active_auths.${agent}.${authId}.expires_at`)
          };
        }
        active_auths[agent] = agentAuths;
      }

      state.concurrency = { max_concurrent, active, active_auths };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  RecursionDepthModule: {
    moduleId: "RecursionDepthModule",
    serializeState(state: State): unknown {
      return normalizeRecursion(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.recursion = { max_depth: {} };
        return;
      }
      const obj = asObject(payload, "recursion");
      const maxObj = asObject(obj.max_depth ?? {}, "recursion.max_depth");
      const max_depth: Record<string, number> = {};
      for (const agent of Object.keys(maxObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        max_depth[agent] = assertNonNegInt(maxObj[agent], `recursion.max_depth.${agent}`);
      }
      state.recursion = { max_depth };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  ToolAmplificationModule: {
    moduleId: "ToolAmplificationModule",
    serializeState(state: State): unknown {
      return normalizeToolLimits(state);
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.tool_limits = { window_seconds: 1, max_calls: {}, max_calls_by_tool: {}, calls: {} };
        return;
      }
      const obj = asObject(payload, "tool_limits");
      const maxCallsObj = asObject(obj.max_calls ?? {}, "tool_limits.max_calls");
      const byToolObj = asObject(obj.max_calls_by_tool ?? {}, "tool_limits.max_calls_by_tool");
      const callsObj = asObject(obj.calls ?? {}, "tool_limits.calls");

      const max_calls: Record<string, number> = {};
      for (const agent of Object.keys(maxCallsObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        max_calls[agent] = assertNonNegInt(maxCallsObj[agent], `tool_limits.max_calls.${agent}`);
      }

      const max_calls_by_tool: Record<string, Record<string, number>> = {};
      for (const agent of Object.keys(byToolObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        const toolsObj = asObject(byToolObj[agent] ?? {}, `tool_limits.max_calls_by_tool.${agent}`);
        const tools: Record<string, number> = {};
        for (const tool of Object.keys(toolsObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
          tools[tool] = assertNonNegInt(toolsObj[tool], `tool_limits.max_calls_by_tool.${agent}.${tool}`);
        }
        max_calls_by_tool[agent] = tools;
      }

      const calls: Record<string, Array<{ ts: number; tool?: string }>> = {};
      for (const agent of Object.keys(callsObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        const entries = callsObj[agent];
        if (!Array.isArray(entries)) throw new Error(`invalid tool_limits.calls.${agent}`);
        calls[agent] = entries
          .map((entry, index) => {
            const e = asObject(entry, `tool_limits.calls.${agent}[${index}]`);
            const tool = e.tool === null ? undefined : e.tool;
            if (tool !== undefined && typeof tool !== "string") {
              throw new Error(`invalid tool_limits.calls.${agent}[${index}].tool`);
            }
            return {
              ts: assertInt(e.ts, `tool_limits.calls.${agent}[${index}].ts`),
              tool
            };
          })
          .sort((a, b) => (a.ts - b.ts) || ((a.tool ?? "") < (b.tool ?? "") ? -1 : (a.tool ?? "") > (b.tool ?? "") ? 1 : 0));
      }

      state.tool_limits = {
        window_seconds: assertPosInt(obj.window_seconds, "tool_limits.window_seconds"),
        max_calls,
        max_calls_by_tool,
        calls
      };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  },

  KillSwitchModule: {
    moduleId: "KillSwitchModule",
    serializeState(state: State): unknown {
      const agents: Record<string, boolean> = {};
      for (const agent of sortedKeys(state.kill_switch.agents)) {
        const value = state.kill_switch.agents[agent];
        if (value === undefined) continue;
        agents[agent] = Boolean(value);
      }
      return { global: state.kill_switch.global, agents };
    },
    deserializeState(state: State, payload: unknown): void {
      if (payload === undefined) {
        state.kill_switch = { global: false, agents: {} };
        return;
      }
      const obj = asObject(payload, "kill_switch");
      if (typeof obj.global !== "boolean") throw new Error("invalid kill_switch.global");
      const agentsObj = asObject(obj.agents ?? {}, "kill_switch.agents");
      const agents: Record<string, boolean> = {};
      for (const agent of Object.keys(agentsObj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
        if (typeof agentsObj[agent] !== "boolean") throw new Error(`invalid kill_switch.agents.${agent}`);
        agents[agent] = agentsObj[agent] as boolean;
      }
      state.kill_switch = { global: obj.global, agents };
    },
    stateHash(state: State): StateHash {
      return hashPayload(this.serializeState(state));
    }
  }
};

export function statelessModuleCodec(moduleId: string): ModuleStateCodec {
  const codec = MODULE_CODECS[moduleId];
  if (!codec) {
    throw new Error(`unknown module codec: ${moduleId}`);
  }
  return codec;
}
