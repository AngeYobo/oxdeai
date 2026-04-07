// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { Authorization } from "../types/authorization.js";

const INTENT_BINDING_FIELDS = [
  "intent_id",
  "agent_id",
  "action_type",
  "depth",
  "amount",
  "asset",
  "target",
  "timestamp",
  "metadata_hash",
  "nonce",
  "type",
  "authorization_id",
  "tool",
  "tool_call"
] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}
/** @public */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}
/** @public */
export function sha256HexFromJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
/** @public */
export function intentHash(intent: Intent): string {
  const src = intent as unknown as Record<string, unknown>;
  const binding: Record<string, unknown> = {};
  for (const key of INTENT_BINDING_FIELDS) {
    const value = src[key];
    if (value !== undefined) binding[key] = value;
  }
  return sha256HexFromJson(binding);
}
/** @public */
export function stateSnapshotHash(state: State): string {
  return sha256HexFromJson(state);
}
/** @public */
export function authPayloadString(auth: Omit<Authorization, "engine_signature">): string {
  return canonicalJson(auth);
}
