// SPDX-License-Identifier: Apache-2.0
import type { SiftReceipt } from "./verifyReceipt.js";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface OxDeAIIntent {
  type: "EXECUTE";
  tool: string;
  params: Record<string, NormalizedIntentValue>;
}

export type NormalizedIntentValue =
  | string
  | number
  | boolean
  | null
  | NormalizedIntentValue[]
  | { [key: string]: NormalizedIntentValue };

export interface NormalizeIntentInput {
  receipt: SiftReceipt;
  params: unknown;
  expectedAction?: string;
  expectedTool?: string;
}

export type NormalizeIntentErrorCode =
  | "INVALID_PARAMS"
  | "AMBIGUOUS_INTENT"
  | "ACTION_MISMATCH"
  | "TOOL_MISMATCH"
  | "UNSUPPORTED_PARAM_TYPE"
  | "NON_DETERMINISTIC_INPUT";

export type NormalizeIntentResult =
  | { ok: true; intent: OxDeAIIntent }
  | { ok: false; code: NormalizeIntentErrorCode; message: string };

// ─── Internal helpers ─────────────────────────────────────────────────────────

function fail(code: NormalizeIntentErrorCode, message: string): NormalizeIntentResult {
  return { ok: false, code, message };
}

/**
 * Strict plain-object test: must have Object.prototype or null as prototype.
 * Rejects Date, Map, Set, Buffer, Uint8Array, and all other class instances.
 * The repository's shared isPlainObject helpers do NOT check prototype and
 * therefore accept class instances — this stricter version is intentional.
 */
function isStrictPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

// ─── Recursive param normalization ────────────────────────────────────────────

type NormalizeOk = { _tag: "ok"; value: NormalizedIntentValue };
type NormalizeErr = { _tag: "error"; code: NormalizeIntentErrorCode; message: string };

function err(code: NormalizeIntentErrorCode, message: string): NormalizeErr {
  return { _tag: "error", code, message };
}

/**
 * Recursively normalizes a single param value. Fails immediately on any
 * unsupported or ambiguous type anywhere in the tree.
 *
 * Accepted leaf types:  null, boolean, string, safe integer
 * Accepted containers:  plain objects (prototype-checked), arrays
 * Rejected explicitly:  float, NaN, Infinity, bigint, symbol, undefined,
 *                       function, Date, Map, Set, Buffer, Uint8Array,
 *                       class instances, objects with empty string keys
 *
 * Object keys are preserved as-is (not sorted here — sorting is the
 * responsibility of the later canonicalization step).
 */
function normalizeValue(value: unknown, path: string): NormalizeOk | NormalizeErr {
  // ── null ──────────────────────────────────────────────────────────────────
  if (value === null) return { _tag: "ok", value: null };

  // ── boolean ───────────────────────────────────────────────────────────────
  if (typeof value === "boolean") return { _tag: "ok", value };

  // ── string ────────────────────────────────────────────────────────────────
  if (typeof value === "string") return { _tag: "ok", value };

  // ── number — safe integers only ───────────────────────────────────────────
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      // Covers: floats, NaN, ±Infinity, numbers outside ±(2^53 - 1)
      return err(
        "UNSUPPORTED_PARAM_TYPE",
        `Value at '${path}' is not a safe integer (floats, NaN, and Infinity are not allowed)`
      );
    }
    return { _tag: "ok", value };
  }

  // ── array — recurse preserving order ─────────────────────────────────────
  if (Array.isArray(value)) {
    const out: NormalizedIntentValue[] = [];
    for (let i = 0; i < value.length; i++) {
      const r = normalizeValue(value[i], `${path}[${i}]`);
      if (r._tag === "error") return r;
      out.push(r.value);
    }
    return { _tag: "ok", value: out };
  }

  // ── plain object — prototype-checked, keys preserved ─────────────────────
  if (isStrictPlainObject(value)) {
    // Use Object.create(null) so a key named "__proto__" is stored as an own
    // data property rather than invoking the Object.prototype setter.
    const out = Object.create(null) as { [key: string]: NormalizedIntentValue };
    for (const key of Object.keys(value)) {
      if (key === "") {
        return err("INVALID_PARAMS", `Empty string key found at '${path}'`);
      }
      const r = normalizeValue(value[key], `${path}.${key}`);
      if (r._tag === "error") return r;
      out[key] = r.value;
    }
    return { _tag: "ok", value: out };
  }

  // ── everything else is explicitly rejected ────────────────────────────────
  // bigint, symbol, function, undefined, Date, Map, Set, Buffer, class instances
  const typeLabel =
    typeof value === "object"
      ? Object.prototype.toString.call(value) // e.g. [object Date], [object Map]
      : typeof value;
  return err(
    "UNSUPPORTED_PARAM_TYPE",
    `Value at '${path}' has an unsupported type: ${typeLabel}`
  );
}

// ─── Main exported function ───────────────────────────────────────────────────

/**
 * Normalizes a verified Sift receipt and explicit execution params into a
 * deterministic OxDeAI intent object.
 *
 * The receipt supplies the target tool identity; the caller MUST supply
 * explicit params — a receipt alone is never sufficient to construct an
 * executable intent.
 *
 * PARAMETER BINDING GUARANTEE (read before use):
 *   Sift receipts do NOT include or cryptographically bind parameter values.
 *   The `intent_hash` computed downstream (in receiptToAuthorization) commits
 *   to the params supplied HERE by the caller — NOT to the params that Sift
 *   evaluated when it issued the receipt.
 *
 *   Therefore: Sift provides action-level authorization (tool identity +
 *   policy match), NOT parameter-level cryptographic binding.  A mismatch
 *   between the params Sift evaluated and the params the adapter supplies is
 *   NOT detectable from the receipt alone.
 *
 *   If parameter-level guarantees are required, Sift MUST include a
 *   params_hash (SHA-256 of canonical params) in the signed receipt payload,
 *   and the adapter MUST verify it before calling this function.
 *
 * Only `type`, `tool`, and normalized `params` appear in the intent.
 * All receipt governance fields (timestamp, nonce, receipt_hash, signature,
 * tenant_id, agent_id, policy_matched, risk_tier, action) are intentionally
 * excluded from the output.
 *
 * Fails closed: any ambiguity or unsupported type returns `{ ok: false }`.
 */
export function normalizeIntent(input: NormalizeIntentInput): NormalizeIntentResult {
  try {
    const { receipt, params, expectedAction, expectedTool } = input;

    // ── 1. Action validation ─────────────────────────────────────────────────
    if (expectedAction !== undefined && receipt.action !== expectedAction) {
      return fail(
        "ACTION_MISMATCH",
        `Expected action '${expectedAction}' but receipt has '${receipt.action}'`
      );
    }

    // ── 2. Tool validation ───────────────────────────────────────────────────
    if (expectedTool !== undefined && receipt.tool !== expectedTool) {
      return fail(
        "TOOL_MISMATCH",
        `Expected tool '${expectedTool}' but receipt has '${receipt.tool}'`
      );
    }

    // Defense-in-depth: receipt.tool is guaranteed non-empty by SiftReceipt
    // invariants established in verifyReceipt, but fail closed regardless.
    if (typeof receipt.tool !== "string" || receipt.tool.length === 0) {
      return fail("AMBIGUOUS_INTENT", "Receipt tool is missing or empty");
    }

    // ── 3. Params requirement ────────────────────────────────────────────────
    // A receipt alone must never be sufficient to construct an executable
    // intent. params MUST be explicitly supplied by the caller.
    if (params === undefined || params === null) {
      return fail(
        "AMBIGUOUS_INTENT",
        "Explicit params are required; a Sift receipt alone is not sufficient to construct executable intent"
      );
    }

    // Top-level params must be a plain object.
    // Arrays, primitives, and class instances are not allowed at this level.
    if (!isStrictPlainObject(params)) {
      return fail(
        "INVALID_PARAMS",
        "params must be a plain object; arrays and primitives are not allowed at the top level"
      );
    }

    // ── 4. Deterministic param normalization ─────────────────────────────────
    const normalizedParams = Object.create(null) as Record<string, NormalizedIntentValue>;

    for (const key of Object.keys(params)) {
      if (key === "") {
        return fail("INVALID_PARAMS", "Empty string keys are not allowed in params");
      }
      const r = normalizeValue(params[key], key);
      if (r._tag === "error") {
        return fail(r.code, r.message);
      }
      normalizedParams[key] = r.value;
    }

    // ── 5. Construct intent ──────────────────────────────────────────────────
    // Only type, tool, and params. No receipt metadata.
    return {
      ok: true,
      intent: {
        type: "EXECUTE",
        tool: receipt.tool,
        params: normalizedParams,
      },
    };
  } catch (e) {
    return fail(
      "NON_DETERMINISTIC_INPUT",
      `Unexpected error during intent normalization: ${e instanceof Error ? e.message : String(e)}`
    );
  }
}
