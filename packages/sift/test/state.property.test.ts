// SPDX-License-Identifier: Apache-2.0

/**
 * Property-based tests for normalizeState.
 *
 * Each property verifies an OxDeAI execution-boundary invariant:
 *   P1  Determinism          — same input always produces same output
 *   P2  __proto__ own key    — preserved as own data property, prototype intact
 *   P3  Required keys        — present key passes; absent key fails with known code
 *   P4  Unsupported values   — fail closed without throwing
 *   P5  Floats               — always fail, never silently coerced
 *   P6  Invalid top-level    — non-plain-object roots always fail
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fc from "fast-check";

import {
  normalizeState,
  type NormalizeStateResult,
} from "../src/state.js";
import {
  arbDeterministicObject,
  arbDeterministicValue,
  arbPojoWithProtoKey,
  arbUnsupportedValue,
} from "./helpers/propertyArbitraries.js";

// ─── Run budget ───────────────────────────────────────────────────────────────

/** Default run count. 200 gives good coverage without being slow. */
const RUNS = 200;
/**
 * Reduced run count for properties that use .chain() or .filter() internally.
 * Shrinking with dependent generators is more expensive.
 */
const RUNS_CHAIN = 100;

// ─── P1. Determinism ──────────────────────────────────────────────────────────

test("P1: normalizeState is deterministic — same input always produces the same output", () => {
  fc.assert(
    fc.property(
      arbDeterministicObject(),
      (state: Record<string, unknown>) => {
        const r1 = normalizeState({ state });
        const r2 = normalizeState({ state });
        // deepStrictEqual checks prototype equality on nested objects:
        // both r1.state and r2.state are Object.create(null), so prototypes match.
        assert.deepStrictEqual(r1, r2);
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P2. Own __proto__ key preservation ───────────────────────────────────────

test("P2: normalizeState preserves __proto__ as own data property and never mutates the prototype chain", () => {
  fc.assert(
    fc.property(
      arbPojoWithProtoKey(),
      (state: Record<string, unknown>) => {
        const protoValBefore = state["__proto__"];

        const result = normalizeState({ state });

        assert.equal(
          result.ok,
          true,
          "normalization must succeed for valid state containing __proto__ as own key"
        );
        if (!result.ok) return;

        // __proto__ must survive as an own enumerable property on the output,
        // not be silently dropped or interpreted as a prototype assignment.
        assert.equal(
          Object.prototype.hasOwnProperty.call(result.state, "__proto__"),
          true,
          "__proto__ must be an own property of the normalized state object"
        );

        // The stored value must be identical to what was supplied.
        assert.deepStrictEqual(
          result.state["__proto__"],
          protoValBefore,
          "__proto__ value must be preserved without modification"
        );

        // The output object is always Object.create(null); its prototype must
        // never be changed to anything else regardless of input key names.
        assert.equal(
          Object.getPrototypeOf(result.state),
          null,
          "normalized state prototype must be null — __proto__ key must not mutate the prototype chain"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P3. Required keys enforcement ───────────────────────────────────────────

test("P3a: normalizeState succeeds when a required top-level key is present in state", () => {
  // Generate an object guaranteed to have at least one key, then pick one of
  // those keys as the required key.
  const arbStateWithRequiredKey = fc
    .dictionary(
      fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => k !== "__proto__"),
      arbDeterministicValue(1),
      { minKeys: 1, maxKeys: 6 }
    )
    .chain((state: Record<string, unknown>) => {
      const keys = Object.keys(state);
      // Derive the picked key deterministically so shrinking stays coherent.
      const key = keys[Math.floor(keys.length / 2)]!;
      return fc.constant({ state, key });
    });

  fc.assert(
    fc.property(
      arbStateWithRequiredKey,
      ({ state, key }: { state: Record<string, unknown>; key: string }) => {
        const result = normalizeState({ state, requiredKeys: [key] });
        assert.equal(
          result.ok,
          true,
          `normalization must succeed when required key '${key}' is present`
        );
      }
    ),
    { numRuns: RUNS_CHAIN }
  );
});

test("P3b: normalizeState returns MISSING_REQUIRED_STATE_KEY when a required key is absent", () => {
  // Derive a key that is guaranteed absent from the generated state.
  const arbStateAndMissingKey = arbDeterministicObject(1).chain(
    (state: Record<string, unknown>) => {
      const existingKeys = new Set(Object.keys(state));
      return fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => !existingKeys.has(k) && k !== "__proto__")
        .map((missingKey: string) => ({ state, missingKey }));
    }
  );

  fc.assert(
    fc.property(
      arbStateAndMissingKey,
      ({
        state,
        missingKey,
      }: {
        state: Record<string, unknown>;
        missingKey: string;
      }) => {
        const result = normalizeState({ state, requiredKeys: [missingKey] });

        assert.equal(
          result.ok,
          false,
          `normalization must fail when required key '${missingKey}' is absent`
        );
        if (!result.ok) {
          assert.equal(
            result.code,
            "MISSING_REQUIRED_STATE_KEY",
            "error code must be MISSING_REQUIRED_STATE_KEY"
          );
        }
      }
    ),
    { numRuns: RUNS_CHAIN }
  );
});

// ─── P4. Unsupported values fail closed ───────────────────────────────────────

test("P4: normalizeState fails closed on unsupported values nested in state — never throws", () => {
  // Wrap the unsupported value as a field inside an otherwise-valid object so
  // that the failure is triggered by recursive value validation, not by the
  // top-level shape guard (which is tested separately in P6).
  const arbStateWithUnsupportedNested = fc
    .tuple(
      fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => k !== "__proto__"),
      arbUnsupportedValue()
    )
    .map(([key, badVal]: [string, unknown]) => ({ [key]: badVal }));

  fc.assert(
    fc.property(
      arbStateWithUnsupportedNested,
      (state: Record<string, unknown>) => {
        let result: NormalizeStateResult;
        try {
          result = normalizeState({ state });
        } catch (e) {
          assert.fail(
            `normalizeState threw instead of returning { ok: false }: ${String(e)}`
          );
          return;
        }
        assert.equal(
          result.ok,
          false,
          "normalization must return { ok: false } for state containing an unsupported nested value"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P5. Floats always fail ───────────────────────────────────────────────────

test("P5: non-integer finite floats anywhere in state always cause normalization to fail", () => {
  const nonIntegerFloat = fc
    .float({ noNaN: true, noDefaultInfinity: true })
    .filter((n: number) => !Number.isInteger(n));

  const arbStateWithFloat = fc
    .tuple(
      fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => k !== "__proto__"),
      nonIntegerFloat
    )
    .map(([key, floatVal]: [string, number]) => ({ [key]: floatVal }));

  fc.assert(
    fc.property(
      arbStateWithFloat,
      (state: Record<string, unknown>) => {
        const result = normalizeState({ state });
        assert.equal(
          result.ok,
          false,
          "state containing a float must not normalize successfully — floats are never silently coerced to integers"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P6. Invalid top-level roots fail ────────────────────────────────────────

test("P6: invalid top-level state (null, undefined, array, primitive) always fails", () => {
  // These are rejected at the top-level shape guard before any field
  // normalization is attempted. Covers both the null/primitive paths and the
  // class-instance path (Date, Map, Set have non-Object.prototype prototypes
  // and therefore fail isStrictPlainObject regardless of their contents).
  const arbInvalidRoot: fc.Arbitrary<unknown> = fc.oneof(
    fc.constant(null),
    fc.constant(undefined),
    fc.array(arbDeterministicValue(1), { maxLength: 5 }),
    fc.string({ minLength: 0, maxLength: 32 }),
    fc.integer({ min: -100_000, max: 100_000 }),
    fc.boolean(),
    fc.constant(new Date("2026-01-01T00:00:00.000Z")),
    fc.constant(new Map<string, string>()),
    fc.constant(new Set<number>()),
    fc.constant(Buffer.from("data")),
    fc.constant(new Uint8Array([0, 1]))
  );

  fc.assert(
    fc.property(arbInvalidRoot, (invalidRoot: unknown) => {
      let result: NormalizeStateResult;
      try {
        result = normalizeState({ state: invalidRoot });
      } catch (e) {
        assert.fail(
          `normalizeState threw on invalid top-level root instead of returning { ok: false }: ${String(e)}`
        );
        return;
      }
      assert.equal(
        result.ok,
        false,
        "normalization must fail for any non-plain-object top-level state"
      );
    }),
    { numRuns: RUNS }
  );
});
