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
function normalizeString(value: string): string {
  return value.normalize("NFC");
}
function sortUtf8Lex(keys: string[]): string[] {
  return [...keys].sort((a, b) =>
    Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))
  );
}
function canonicalizeToJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(normalizeString(value));
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("FLOAT_NOT_ALLOWED");
    if (!Number.isSafeInteger(value)) throw new Error("UNSAFE_INTEGER_NUMBER");
    return String(value);
  }
  if (typeof value === "bigint") return JSON.stringify(String(value));
  if (typeof value === "undefined" || typeof value === "function" || typeof value === "symbol") {
    throw new Error("UNSUPPORTED_TYPE");
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeToJson).join(",")}]`;
  if (isPlainObject(value)) {
    const normalizedEntries = Object.entries(value).map(([k, v]) => [normalizeString(k), v] as const);
    const seen = new Set<string>();
    for (const [k] of normalizedEntries) {
      if (seen.has(k)) throw new Error("DUPLICATE_KEY");
      seen.add(k);
    }
    const sortedKeys = sortUtf8Lex(normalizedEntries.map(([k]) => k));
    const parts = sortedKeys.map((key) => {
      const entry = normalizedEntries.find(([k]) => k === key);
      if (!entry) throw new Error("KEY_RESOLUTION_FAILED");
      const [, child] = entry;
      if (key === "ts") {
        if (typeof child !== "number" || !Number.isInteger(child) || !Number.isSafeInteger(child)) {
          throw new Error("INVALID_TIMESTAMP");
        }
      }
      return `${JSON.stringify(key)}:${canonicalizeToJson(child)}`;
    });
    return `{${parts.join(",")}}`;
  }
  throw new Error("UNSUPPORTED_TYPE");
}
function stripUndefinedDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripUndefinedDeep);
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (v !== undefined) out[k] = stripUndefinedDeep(v);
    }
    return out;
  }
  return value;
}
/** @public */
export function canonicalJson(value: unknown): string {
  return canonicalizeToJson(value);
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
  return sha256HexFromJson(stripUndefinedDeep(binding));
}
/** @public */
export function stateSnapshotHash(state: State): string {
  return sha256HexFromJson(stripUndefinedDeep(state));
}
/** @public */
export function authPayloadString(auth: Omit<Authorization, "engine_signature">): string {
  return canonicalJson(stripUndefinedDeep(auth));
}
