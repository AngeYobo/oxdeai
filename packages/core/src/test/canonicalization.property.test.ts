// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based tests for canonicalization-v1 — @oxdeai/core.
 *
 * Every property maps directly to a normative invariant in
 * docs/spec/core/canonicalization-v1.md (§ references inline).
 * No property is included that cannot be grounded in the spec.
 *
 * Uses fast-check with a fixed seed so runs are fully reproducible.
 *   FC_SEED  — override PRNG seed        (default 20260420)
 *   FC_RUNS  — override iterations/test  (default 200)
 *
 * Test IDs: C-P1 through C-P9.
 * Do NOT merge or reorder these with the locked vector suite
 * (docs/spec/test-vectors/canonicalization-v1.json).
 */

import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { canonicalJson, sha256HexFromJson } from "../crypto/hashes.js";

// ── Config ─────────────────────────────────────────────────────────────────────

const SEED = Number(process.env.FC_SEED ?? "20260420");
const RUNS = Number(process.env.FC_RUNS ?? "200");
const fcOpts = { seed: SEED, numRuns: RUNS };

// ── Key pool ───────────────────────────────────────────────────────────────────
// Fixed ASCII pool: controlled, distinct, no "ts" (timestamp key has special semantics §6).
// Using a pool rather than open-ended string generation improves shrink quality.

const KEY_POOL = [
  "action", "agent", "amount", "budget", "depth",
  "id",     "kind",  "label",  "meta",   "model",
  "name",   "nonce", "rate",   "scope",  "state",
  "target", "token", "type",   "user",   "version",
] as const;

const keyArb = fc.constantFrom(...KEY_POOL);

// ── NFC/NFD character pairs ────────────────────────────────────────────────────
// Spec §6: "Strings: normalize to Unicode NFC."
// Each pair is two distinct JS strings (different byte sequences) that share the
// same NFC precomposed form. Used for both string-value and key normalization tests.

const NFC_NFD_CHARS = [
  { nfd: "e\u0301", nfc: "\u00e9" },   // é
  { nfd: "n\u0303", nfc: "\u00f1" },   // ñ
  { nfd: "u\u0308", nfc: "\u00fc" },   // ü
  { nfd: "a\u0300", nfc: "\u00e0" },   // à
  { nfd: "a\u0302", nfc: "\u00e2" },   // â
  { nfd: "c\u0327", nfc: "\u00e7" },   // ç
] as const;

// ── Arbitraries ────────────────────────────────────────────────────────────────

// Full safe-integer range per spec §8.
const safeIntArb = fc.integer({ min: -9007199254740991, max: 9007199254740991 });

// Leaf values: null | boolean | safe integer | ASCII string.
// grapheme-ascii strings are NFC-safe and never trigger normalization surprises.
const leafArb: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 2, arbitrary: fc.boolean() },
  { weight: 3, arbitrary: safeIntArb },
  { weight: 3, arbitrary: fc.string({ unit: "grapheme-ascii", minLength: 0, maxLength: 16 }) },
);

// Shallow object: 2–5 entries, unique keys from pool, leaf values.
const shallowObjectArb: fc.Arbitrary<Record<string, unknown>> = fc
  .uniqueArray(fc.tuple(keyArb, leafArb), {
    selector: ([k]) => k,
    minLength: 2,
    maxLength: 5,
  })
  .map(entries => Object.fromEntries(entries));

// Nested object: outer keys from pool; some values are shallow inner objects.
// Two levels of nesting exercise deepRotate's recursive key permutation.
const nestedObjectArb: fc.Arbitrary<Record<string, unknown>> = shallowObjectArb.chain(inner =>
  fc
    .uniqueArray(
      fc.tuple(
        keyArb,
        fc.oneof({ weight: 3, arbitrary: leafArb }, { weight: 1, arbitrary: fc.constant(inner) }),
      ),
      { selector: ([k]) => k, minLength: 2, maxLength: 4 },
    )
    .map(entries => Object.fromEntries(entries))
);

// ── Helpers ────────────────────────────────────────────────────────────────────

// Rotate object key insertion order by `pivot` positions.
// Rotation is a proper permutation; fast-check can shrink `pivot` independently
// without losing the property counterexample.
function rotateKeys(obj: Record<string, unknown>, pivot: number): Record<string, unknown> {
  const keys = Object.keys(obj);
  if (keys.length === 0) return obj;
  const p = ((pivot % keys.length) + keys.length) % keys.length;
  const out: Record<string, unknown> = {};
  for (const k of [...keys.slice(p), ...keys.slice(0, p)]) out[k] = obj[k];
  return out;
}

// Recursively rotate all object key insertion orders.
// Arrays are intentionally left unmodified — spec §6 states:
// "Arrays: preserve element order."
function deepRotate(value: unknown, pivot: number): unknown {
  if (Array.isArray(value)) return value.map(v => deepRotate(v, pivot));
  if (value !== null && typeof value === "object") {
    const rotated = rotateKeys(value as Record<string, unknown>, pivot);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rotated)) out[k] = deepRotate(v, pivot);
    return out;
  }
  return value;
}

// ── Additional helpers ─────────────────────────────────────────────────────────

// Recursively replaces every string (object keys and string values) with its NFD
// decomposed form. Numbers, booleans, null, and array structure are preserved.
//
// Collision safety: only call on objects whose keys are drawn from KEY_POOL or the
// six Unicode NFC codepoints below. For those pools:
//   ASCII keys: NFD(k) === k — invariant, no change, no collision.
//   Unicode NFC keys (é, ñ, ü, à, â, ç): each decomposes to a distinct base letter +
//   combining mark — all NFD forms are mutually distinct, so post-normalization key
//   dedup inside canonicalJson cannot trigger DUPLICATE_KEY.
function toAllNfd(value: unknown): unknown {
  if (typeof value === "string") return value.normalize("NFD");
  if (Array.isArray(value)) return value.map(toAllNfd);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k.normalize("NFD")] = toAllNfd(v);
    }
    return out;
  }
  return value;
}

// Extended key arbitrary: existing ASCII pool + six Unicode NFC codepoints.
// Each codepoint decomposes to a distinct NFD sequence (verified by inspection),
// so toAllNfd is injective over any object whose keys come from this combined pool.
const extKeyArb: fc.Arbitrary<string> = fc.oneof(
  keyArb,
  fc.constantFrom("\u00e9", "\u00f1", "\u00fc", "\u00e0", "\u00e2", "\u00e7"),
);

// ── Round-trip arbitraries (C-P10) ────────────────────────────────────────────

// Round-trip leaf: null | bool | safe int | ASCII string | NFC Unicode string |
// NFD Unicode string.
//
// Including NFD strings exercises the key stability claim: canonicalJson normalizes
// input strings to NFC on the first pass; JSON.parse of the resulting canonical bytes
// yields NFC strings; re-canonicalizing those NFC strings must return the same bytes.
const rtLeafArb: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 2, arbitrary: fc.boolean() },
  { weight: 3, arbitrary: safeIntArb },
  { weight: 2, arbitrary: fc.string({ unit: "grapheme-ascii", minLength: 0, maxLength: 12 }) },
  { weight: 1, arbitrary: fc.array(fc.constantFrom(...NFC_NFD_CHARS), { minLength: 1, maxLength: 3 })
      .map(pairs => pairs.map(p => p.nfc).join("")) },
  { weight: 1, arbitrary: fc.array(fc.constantFrom(...NFC_NFD_CHARS), { minLength: 1, maxLength: 3 })
      .map(pairs => pairs.map(p => p.nfd).join("")) },
);

// Mid-level: leaf | small array of leaves (depth 2)
const rtMidArb: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 5, arbitrary: rtLeafArb },
  { weight: 2, arbitrary: fc.array(rtLeafArb, { minLength: 0, maxLength: 4 }) },
);

// Shallow RT object: ASCII keys only, mid-level values
const rtShallowObjArb: fc.Arbitrary<Record<string, unknown>> = fc
  .uniqueArray(fc.tuple(keyArb, rtMidArb), {
    selector: ([k]) => k,
    minLength: 1,
    maxLength: 4,
  })
  .map(entries => Object.fromEntries(entries));

// Full round-trip input: leaves, arrays, nested objects, arrays of objects (depth ≤ 4).
// Structural variety is intentional: the property must hold for every valid shape,
// not just flat records.
const rtValueArb: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 1, arbitrary: rtLeafArb },
  { weight: 1, arbitrary: fc.array(rtLeafArb, { minLength: 0, maxLength: 5 }) },
  { weight: 3, arbitrary: rtShallowObjArb },
  // Nested object: outer keys → inner object | leaf | array of objects (depth 3–4)
  { weight: 3, arbitrary: rtShallowObjArb.chain(inner =>
      fc.uniqueArray(
        fc.tuple(keyArb, fc.oneof(
          { weight: 3, arbitrary: rtMidArb },
          { weight: 2, arbitrary: fc.constant(inner) },
          { weight: 1, arbitrary: fc.array(rtShallowObjArb, { minLength: 1, maxLength: 2 }) },
        )),
        { selector: ([k]) => k, minLength: 2, maxLength: 4 },
      ).map(entries => Object.fromEntries(entries))
    )
  },
  { weight: 1, arbitrary: fc.array(rtShallowObjArb, { minLength: 1, maxLength: 3 }) },
);

// ── Normalization equivalence arbitraries (C-P11) ─────────────────────────────

// NFC leaf: exclusively NFC so toAllNfd produces a non-trivial NFD variant.
const nfcLeafArb: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 2, arbitrary: fc.boolean() },
  { weight: 3, arbitrary: safeIntArb },
  { weight: 2, arbitrary: fc.string({ unit: "grapheme-ascii", minLength: 0, maxLength: 12 }) },
  { weight: 2, arbitrary: fc.array(fc.constantFrom(...NFC_NFD_CHARS), { minLength: 1, maxLength: 4 })
      .map(pairs => pairs.map(p => p.nfc).join("")) },
);

// NFC shallow object: extended keys (incl. Unicode NFC) + NFC leaves.
// Using extKeyArb here means toAllNfd will vary BOTH keys and values — the full
// normalization surface is exercised.
const nfcShallowObjArb: fc.Arbitrary<Record<string, unknown>> = fc
  .uniqueArray(fc.tuple(extKeyArb, nfcLeafArb), {
    selector: ([k]) => k,
    minLength: 2,
    maxLength: 4,
  })
  .map(entries => Object.fromEntries(entries));

// NFC nested object: two-level structure. Outer keys may be ASCII or Unicode NFC;
// inner values may be leaves, nested objects, or arrays of leaves.
const nfcNestedObjArb: fc.Arbitrary<Record<string, unknown>> = nfcShallowObjArb.chain(inner =>
  fc
    .uniqueArray(
      fc.tuple(
        extKeyArb,
        fc.oneof(
          { weight: 3, arbitrary: nfcLeafArb },
          { weight: 1, arbitrary: fc.constant(inner) },
          { weight: 1, arbitrary: fc.array(nfcLeafArb, { minLength: 0, maxLength: 3 }) },
        ),
      ),
      { selector: ([k]) => k, minLength: 2, maxLength: 4 },
    )
    .map(entries => Object.fromEntries(entries))
);

// ─────────────────────────────────────────────────────────────────────────────
// C-P1: Determinism
// Spec §2: "The canonicalization function MUST guarantee deterministic
// serialization."
//
// Three successive calls with the same input must return byte-identical output.
// Guards against hidden mutable state, lazy normalization, or non-deterministic
// object key iteration.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P1: canonicalJson returns byte-identical output on repeated calls", () => {
  fc.assert(
    fc.property(
      fc.oneof({ weight: 2, arbitrary: leafArb }, { weight: 3, arbitrary: shallowObjectArb }),
      value => {
        const first = canonicalJson(value);
        return first === canonicalJson(value) && first === canonicalJson(value);
      },
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P2: Key-order invariance
// Spec §6: "Object keys: NFC-normalize, reject duplicates after normalization,
// then sort keys by byte-wise UTF-8 order."
//
// Any permutation of object key insertion order must produce the same canonical
// JSON string. deepRotate covers all nesting levels — a shallow rotation leaving
// nested keys ordered would be an incomplete test.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P2: canonical output is invariant to object key insertion order at every nesting level", () => {
  fc.assert(
    fc.property(
      nestedObjectArb,
      fc.integer({ min: 1, max: 1000 }),
      (obj, pivot) =>
        canonicalJson(obj) === canonicalJson(deepRotate(obj, pivot) as Record<string, unknown>),
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P3: Hash stability across key permutations
// Spec §2: "byte-stability". SHA-256 of canonical bytes must be identical for
// semantically equivalent objects that differ only in key insertion order.
//
// Validates the full pipeline: canonicalize → SHA-256 is key-order-stable.
// A failure here would mean signing or verification is key-order-dependent,
// which would break cross-language parity.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P3: sha256HexFromJson is stable under key insertion order permutation", () => {
  fc.assert(
    fc.property(
      nestedObjectArb,
      fc.integer({ min: 1, max: 1000 }),
      (obj, pivot) =>
        sha256HexFromJson(obj) ===
        sha256HexFromJson(deepRotate(obj, pivot) as Record<string, unknown>),
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P4a: Unicode NFC normalization — string values
// Spec §6: "Strings: normalize to Unicode NFC; encode as JSON strings."
//
// A string composed of NFD-decomposed characters must canonicalize identically
// to the NFC-precomposed equivalent. Uses a fixed pool of known NFD/NFC pairs
// rather than random Unicode, which avoids generating untested normalization
// edge cases and keeps shrink paths clean.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P4a: NFD and NFC string values canonicalize identically", () => {
  fc.assert(
    fc.property(
      fc.array(fc.constantFrom(...NFC_NFD_CHARS), { minLength: 1, maxLength: 4 }),
      fc.string({ unit: "grapheme-ascii", minLength: 0, maxLength: 6 }),
      (pairs, prefix) => {
        const nfcStr = prefix + pairs.map(p => p.nfc).join("");
        const nfdStr = prefix + pairs.map(p => p.nfd).join("");
        return canonicalJson(nfcStr) === canonicalJson(nfdStr);
      },
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P4b: Unicode NFC normalization — object keys
// Spec §6: "Object keys: NFC-normalize..."
//
// Two objects that differ only in whether a key uses NFD or NFC encoding must
// produce identical canonical JSON, because both keys normalize to the same
// NFC string before sorting and serialization.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P4b: NFD and NFC object keys canonicalize identically", () => {
  fc.assert(
    fc.property(
      fc.constantFrom(...NFC_NFD_CHARS),
      fc.string({ unit: "grapheme-ascii", minLength: 0, maxLength: 6 }),
      leafArb,
      (pair, suffix, value) =>
        canonicalJson({ [pair.nfc + suffix]: value }) ===
        canonicalJson({ [pair.nfd + suffix]: value }),
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P5: Duplicate key after NFC normalization → DUPLICATE_KEY
// Spec §6: "reject duplicates after normalization."
// Spec §7: DUPLICATE_KEY.
//
// An object containing two distinct JS string keys that share the same NFC form
// must be rejected fail-closed. This is a boundary test: key aliasing via
// Unicode normalization must not silently produce output.
//
// "e\u0301" and "\u00e9" are different JS strings (different byte sequences)
// but NFC-normalize to the same codepoint. V8 does not normalize property keys,
// so both properties coexist in the object and Object.entries returns both.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P5: two keys sharing the same NFC form always fail with DUPLICATE_KEY", () => {
  for (const { nfd, nfc } of NFC_NFD_CHARS) {
    const obj: Record<string, unknown> = {};
    obj[nfd] = "first";
    obj[nfc] = "second";

    assert.throws(
      () => canonicalJson(obj),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(
          err.message.includes("DUPLICATE_KEY"),
          `expected DUPLICATE_KEY for "${nfd}" / "${nfc}", got: ${err.message}`,
        );
        return true;
      },
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P6: Floats, NaN, ±Infinity → FLOAT_NOT_ALLOWED
// Spec §6: "floats and NaN/±Inf MUST be rejected."
// Spec §7: FLOAT_NOT_ALLOWED.
//
// Non-integer numbers must be rejected at the top level. Non-integer finites
// are generated as (integer + fractional offset) to avoid fc.double() API
// variation across fast-check versions. NaN and ±Infinity are fixed constants —
// not generatable by fc — but explicitly required by the spec and tested here.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P6: floats, NaN, and ±Infinity are always rejected with FLOAT_NOT_ALLOWED", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: -1_000_000, max: 1_000_000 }),
      fc.integer({ min: 1, max: 9 }),
      (base, frac) => {
        const float = base + frac / 10; // e.g. 5.3, -12.7, 0.1 — never an integer
        assert.throws(
          () => canonicalJson(float),
          (err: unknown) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes("FLOAT_NOT_ALLOWED"),
              `got: ${(err as Error).message}`,
            );
            return true;
          },
        );
      },
    ),
    fcOpts,
  );

  for (const special of [NaN, Infinity, -Infinity]) {
    assert.throws(
      () => canonicalJson(special),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(
          err.message.includes("FLOAT_NOT_ALLOWED"),
          `expected FLOAT_NOT_ALLOWED for ${special}, got: ${(err as Error).message}`,
        );
        return true;
      },
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P7: Unsafe integers → UNSAFE_INTEGER_NUMBER
// Spec §8: "Integers MAY be represented as JSON numbers only if within
// [-(2^53-1), +(2^53-1)]; otherwise they MUST be encoded as strings."
// Spec §7: UNSAFE_INTEGER_NUMBER.
//
// Integers just outside MAX_SAFE_INTEGER / MIN_SAFE_INTEGER must be rejected.
// The offset generator ensures we cover values immediately above and below the
// boundary (offset = 0 → boundary value; larger offsets exercise wider range).
// The caller is responsible for encoding out-of-range integers as BigInt strings.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P7: integers outside the safe IEEE-754 range are rejected with UNSAFE_INTEGER_NUMBER", () => {
  fc.assert(
    fc.property(
      fc.nat({ max: 1_000_000 }).chain(offset =>
        fc.constantFrom(
          Number.MAX_SAFE_INTEGER + 1 + offset,
          -(Number.MAX_SAFE_INTEGER + 1 + offset),
        ),
      ),
      unsafeInt => {
        assert.ok(Number.isInteger(unsafeInt), `precondition: ${unsafeInt} must be integer`);
        assert.throws(
          () => canonicalJson(unsafeInt),
          (err: unknown) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes("UNSAFE_INTEGER_NUMBER"),
              `expected UNSAFE_INTEGER_NUMBER for ${unsafeInt}, got: ${(err as Error).message}`,
            );
            return true;
          },
        );
      },
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P8: Unsupported runtime types → UNSUPPORTED_TYPE
// Spec §6: "function, symbol, undefined...MUST be rejected."
// Spec §7: UNSUPPORTED_TYPE.
//
// Rejection must occur regardless of where the unsupported type appears:
// top-level, as an object value, or as an array element. Covering all three
// structural positions closes the "buried type" attack surface — a nested
// unsupported value must not be silently skipped.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P8: unsupported runtime types are rejected with UNSUPPORTED_TYPE at any structural position", () => {
  const BAD_VALUES: Array<[string, unknown]> = [
    ["undefined (top-level)",        undefined],
    ["function (top-level)",         () => {}],
    ["symbol (top-level)",           Symbol("test")],
    ["undefined in object value",    { a: undefined }],
    ["function in object value",     { a: () => {} }],
    ["symbol in object value",       { a: Symbol("x") }],
    ["undefined in array element",   [undefined]],
    ["function in array element",    [() => {}]],
    ["symbol in array element",      [Symbol("y")]],
  ];

  for (const [label, value] of BAD_VALUES) {
    assert.throws(
      () => canonicalJson(value),
      (err: unknown) => {
        assert.ok(err instanceof Error, `${label}: expected Error`);
        assert.ok(
          err.message.includes("UNSUPPORTED_TYPE"),
          `${label}: expected UNSUPPORTED_TYPE, got: ${(err as Error).message}`,
        );
        return true;
      },
      `${label}: must throw UNSUPPORTED_TYPE`,
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P9: Invalid value under key "ts" → INVALID_TIMESTAMP
// Spec §6: "if key == 'ts', the value MUST be an integer within the safe range;
// otherwise reject."
// Spec §7: INVALID_TIMESTAMP.
//
// Fixed cases cover every disallowed category for the timestamp key.
// The generated sub-test confirms that floats under "ts" are rejected via
// INVALID_TIMESTAMP (not FLOAT_NOT_ALLOWED — the "ts" check fires first).
// ─────────────────────────────────────────────────────────────────────────────

test("C-P9: any non-integer or non-safe value under key 'ts' fails with INVALID_TIMESTAMP", () => {
  const INVALID_TS: Array<[string, unknown]> = [
    ["float",              1712448000.5],
    ["string ISO",         "2024-04-07T00:00:00Z"],
    ["string integer",     "1712448000"],
    ["null",               null],
    ["boolean",            true],
    ["above MAX_SAFE",     Number.MAX_SAFE_INTEGER + 1],
    ["below MIN_SAFE",     -(Number.MAX_SAFE_INTEGER + 1)],
    ["NaN",                NaN],
    ["Infinity",           Infinity],
    ["-Infinity",          -Infinity],
    ["array",              [1712448000]],
    ["nested object",      { epoch: 1712448000 }],
  ];

  for (const [label, tsValue] of INVALID_TS) {
    assert.throws(
      () => canonicalJson({ ts: tsValue }),
      (err: unknown) => {
        assert.ok(err instanceof Error, `ts=${label}: expected Error`);
        assert.ok(
          err.message.includes("INVALID_TIMESTAMP"),
          `ts=${label}: expected INVALID_TIMESTAMP, got: ${(err as Error).message}`,
        );
        return true;
      },
      `ts=${label}: must throw INVALID_TIMESTAMP`,
    );
  }

  // Generated: any float under "ts" → INVALID_TIMESTAMP (ts check precedes type check)
  fc.assert(
    fc.property(
      fc.integer({ min: -1_000_000, max: 1_000_000 }),
      fc.integer({ min: 1, max: 9 }),
      (base, frac) => {
        assert.throws(
          () => canonicalJson({ ts: base + frac / 10 }),
          (err: unknown) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes("INVALID_TIMESTAMP"),
              `got: ${(err as Error).message}`,
            );
            return true;
          },
        );
      },
    ),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P10: Round-trip stability
// Spec §2: "deterministic serialization", "byte-stability".
// Spec §4: "The canonical output MUST be...valid JSON."
//
// For any valid canonicalizable input x:
//   canonical  = canonicalJson(x)
//   canonical2 = canonicalJson(JSON.parse(canonical))
//   canonical2 === canonical
//
// This proves the canonical form is a fixed point under parse → re-canonicalize.
// Failures would indicate one of:
//   (a) NFC normalization is input-dependent and not output-stabilized: a string
//       surviving JSON.parse comes back in a form that canonicalizes differently.
//   (b) Serializer instability at object or array boundaries.
//   (c) key-sort order changes after a round-trip through JSON.parse.
//
// The generator deliberately includes NFD string values to strengthen (a): the
// first canonicalize pass normalizes NFD → NFC; JSON.parse returns NFC; the second
// pass must produce the same bytes. A partial-normalization bug would fail here.
//
// BigInt is excluded: after round-trip it becomes a plain string (42n → "42"),
// which is a type change — the bytes are identical but the type contract differs.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P10: canonical form is a fixed point under JSON.parse → re-canonicalize", () => {
  fc.assert(
    fc.property(rtValueArb, value => {
      const canonical = canonicalJson(value);
      const parsed: unknown = JSON.parse(canonical);
      const canonical2 = canonicalJson(parsed);
      assert.strictEqual(canonical2, canonical, "round-trip produced different canonical bytes");
    }),
    fcOpts,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// C-P11: Normalization equivalence in nested structures
// Spec §6: "Strings: normalize to Unicode NFC."
//          "Object keys: NFC-normalize, reject duplicates after normalization..."
//
// For any NFC input x, its structurally identical NFD twin x_nfd — produced by
// replacing every string value AND every object key with its NFD form — must
// produce the same canonical JSON bytes and the same SHA-256 digest.
//
// This extends C-P4a (flat string values) and C-P4b (single-key objects) to:
//   • nested objects where both keys AND values are NFC/NFD at every depth
//   • arrays of objects with Unicode NFC/NFD keys and values
//   • simultaneous key + value normalization in the same structure
//
// The SHA-256 assertion verifies the full pipeline: normalization must collapse
// into identical digests, not just identical serialized strings.
//
// Generator safety: toAllNfd is collision-free on the combined key pool because:
//   ASCII keys: NFD(k) === k — invariant.
//   Unicode keys (é→e+U+0301, ñ→n+U+0303, ü→u+U+0308, à→a+U+0300, â→a+U+0302,
//   ç→c+U+0327): each decomposes to a distinct base + combiner pair.
// No two distinct NFC keys in this pool share an NFD form → DUPLICATE_KEY cannot
// be triggered by the NFD conversion itself.
// ─────────────────────────────────────────────────────────────────────────────

test("C-P11: normalization-equivalent inputs produce identical canonical output and hash in nested structures", () => {
  fc.assert(
    fc.property(
      fc.oneof(
        { weight: 3, arbitrary: nfcNestedObjArb },
        { weight: 2, arbitrary: fc.array(nfcShallowObjArb, { minLength: 1, maxLength: 3 }) },
      ),
      nfcInput => {
        const nfdInput = toAllNfd(nfcInput);
        assert.strictEqual(
          canonicalJson(nfcInput),
          canonicalJson(nfdInput),
          "NFC and all-NFD variants must produce identical canonical JSON",
        );
        assert.strictEqual(
          sha256HexFromJson(nfcInput),
          sha256HexFromJson(nfdInput),
          "NFC and all-NFD variants must produce identical SHA-256",
        );
      },
    ),
    fcOpts,
  );
});
