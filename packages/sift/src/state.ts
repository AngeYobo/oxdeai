// SPDX-License-Identifier: Apache-2.0

// ─── Public types ─────────────────────────────────────────────────────────────

export type NormalizedStateValue =
  | string
  | number
  | boolean
  | null
  | NormalizedStateValue[]
  | { [key: string]: NormalizedStateValue };

export type NormalizedState = Record<string, NormalizedStateValue>;

export interface NormalizeStateInput {
  state: unknown;
  requiredKeys?: readonly string[];
}

export type NormalizeStateErrorCode =
  | "MISSING_STATE"
  | "INVALID_STATE"
  | "MISSING_REQUIRED_STATE_KEY"
  | "UNSUPPORTED_STATE_VALUE"
  | "NON_DETERMINISTIC_STATE";

export type NormalizeStateResult =
  | { ok: true; state: NormalizedState }
  | { ok: false; code: NormalizeStateErrorCode; message: string };

// ─── Internal helpers ─────────────────────────────────────────────────────────

function fail(code: NormalizeStateErrorCode, message: string): NormalizeStateResult {
  return { ok: false, code, message };
}

/**
 * Strict plain-object guard: accepts only objects with Object.prototype or
 * null prototype. Rejects Date, Map, Set, Buffer, Uint8Array, and all other
 * class instances. The shared repo helpers do NOT check prototype — this
 * stricter version is intentional for untrusted input handling.
 */
function isStrictPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

// ─── Recursive state value normalization ──────────────────────────────────────

type NormalizeOk = { _tag: "ok"; value: NormalizedStateValue };
type NormalizeErr = { _tag: "error"; code: NormalizeStateErrorCode; message: string };

function valueErr(code: NormalizeStateErrorCode, message: string): NormalizeErr {
  return { _tag: "error", code, message };
}

/**
 * Recursively normalizes a single state value. Fails immediately on any
 * unsupported type anywhere in the tree.
 *
 * Accepted leaf types:  null, boolean, string, safe integer
 * Accepted containers:  strict plain objects (prototype-checked), arrays
 * Rejected explicitly:  float, NaN, Infinity, bigint, symbol, undefined,
 *                       function, Date, Map, Set, Buffer, Uint8Array,
 *                       class instances, objects with empty string keys
 *
 * Output objects are created with Object.create(null) to prevent the
 * Object.prototype.__proto__ setter from silently swallowing a key named
 * "__proto__" instead of storing it as an own property. This is the only
 * safe way to faithfully round-trip state that contains such a key.
 *
 * Object keys are preserved in insertion order; sorting is the responsibility
 * of the later canonicalization step.
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
      // Covers: floats, NaN, ±Infinity, numbers outside ±(2^53 − 1)
      return valueErr(
        "UNSUPPORTED_STATE_VALUE",
        `Value at '${path}' is not a safe integer (floats, NaN, and Infinity are not allowed)`
      );
    }
    return { _tag: "ok", value };
  }

  // ── array — recurse, preserve order ───────────────────────────────────────
  if (Array.isArray(value)) {
    const out: NormalizedStateValue[] = [];
    for (let i = 0; i < value.length; i++) {
      const r = normalizeValue(value[i], `${path}[${i}]`);
      if (r._tag === "error") return r;
      out.push(r.value);
    }
    return { _tag: "ok", value: out };
  }

  // ── plain object — prototype-checked, keys preserved ─────────────────────
  if (isStrictPlainObject(value)) {
    // Use Object.create(null) so that a key named "__proto__" is stored as an
    // own data property rather than invoking the Object.prototype setter.
    const out = Object.create(null) as { [key: string]: NormalizedStateValue };
    for (const key of Object.keys(value)) {
      if (key === "") {
        return valueErr("INVALID_STATE", `Empty string key found at '${path}'`);
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
  return valueErr(
    "UNSUPPORTED_STATE_VALUE",
    `Value at '${path}' has an unsupported type: ${typeLabel}`
  );
}

// ─── Main exported function ───────────────────────────────────────────────────

/**
 * Validates and normalizes an explicit execution-relevant state snapshot.
 *
 * State MUST be supplied by the caller. This function does not fetch, infer,
 * or default state from any external source, from the receipt, or from the
 * environment. A missing or invalid state always fails closed.
 *
 * On success, returns a normalized plain object suitable for later
 * canonicalization and SHA-256 hashing. No hashing is performed here.
 *
 * Fails closed: any missing, ambiguous, or unsupported input returns
 * `{ ok: false }`.
 */
export function normalizeState(input: NormalizeStateInput): NormalizeStateResult {
  try {
    const { state, requiredKeys } = input;

    // ── 1. State presence check ──────────────────────────────────────────────
    // null and undefined are both rejected — do not default to {}.
    if (state === undefined || state === null) {
      return fail(
        "MISSING_STATE",
        "State is required; null and undefined are not accepted"
      );
    }

    // ── 2. Top-level shape check ─────────────────────────────────────────────
    // Arrays and primitives are not valid state roots.
    if (!isStrictPlainObject(state)) {
      return fail(
        "INVALID_STATE",
        "State must be a plain object; arrays, primitives, and class instances are not allowed at the top level"
      );
    }

    // ── 3. Recursive normalization ───────────────────────────────────────────
    // Use Object.create(null) for the same reason as in normalizeValue: prevents
    // the __proto__ setter from silently dropping a key named "__proto__".
    const normalizedState = Object.create(null) as NormalizedState;

    for (const key of Object.keys(state)) {
      if (key === "") {
        return fail("INVALID_STATE", "Empty string keys are not allowed in state");
      }
      const r = normalizeValue(state[key], key);
      if (r._tag === "error") {
        return fail(r.code, r.message);
      }
      normalizedState[key] = r.value;
    }

    // ── 4. Required keys validation (top-level only) ─────────────────────────
    if (requiredKeys !== undefined) {
      for (const key of requiredKeys) {
        // hasOwnProperty.call is safe on null-prototype objects because
        // it borrows the method from Object.prototype explicitly.
        if (!Object.prototype.hasOwnProperty.call(normalizedState, key)) {
          return fail(
            "MISSING_REQUIRED_STATE_KEY",
            `Required state key '${key}' is missing`
          );
        }
      }
    }

    // ── 5. Success ───────────────────────────────────────────────────────────
    return { ok: true, state: normalizedState };
  } catch (e) {
    return fail(
      "NON_DETERMINISTIC_STATE",
      `Unexpected error during state normalization: ${e instanceof Error ? e.message : String(e)}`
    );
  }
}
