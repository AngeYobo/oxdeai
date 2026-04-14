// SPDX-License-Identifier: Apache-2.0

/**
 * Reusable fast-check arbitraries for the Sift adapter property tests.
 *
 * Design constraints that mirror the OxDeAI invariants under test:
 *   - deterministic arbitraries contain only values normalization accepts
 *   - "__proto__" is handled explicitly and never via prototype-mutating assignment
 *   - unsupported arbitraries cover every explicitly rejected category
 *   - no floats, NaN, Infinity, or unsafe integers in deterministic arbitraries
 */

import * as fc from "fast-check";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Cast any Arbitrary<T> to Arbitrary<unknown> without losing fast-check metadata. */
function u<T>(a: fc.Arbitrary<T>): fc.Arbitrary<unknown> {
  return a as fc.Arbitrary<unknown>;
}

// ─── Safe integers ─────────────────────────────────────────────────────────────

/**
 * Generates numbers within the safe integer range
 * [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER].
 * Never produces floats, NaN, or Infinity.
 */
export function arbSafeInteger(): fc.Arbitrary<number> {
  return fc.integer({
    min: Number.MIN_SAFE_INTEGER,
    max: Number.MAX_SAFE_INTEGER,
  });
}

// ─── Scalar leaves ─────────────────────────────────────────────────────────────

/**
 * Generates leaf values accepted by normalization:
 *   null | boolean | string | safe integer
 *
 * Does NOT generate floats, NaN, Infinity, bigint, symbol,
 * undefined, or any object type.
 */
export function arbDeterministicScalar(): fc.Arbitrary<
  string | number | boolean | null
> {
  return fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.string({ minLength: 0, maxLength: 48 }),
    arbSafeInteger()
  );
}

// ─── Recursive deterministic values ───────────────────────────────────────────

/**
 * Generates any value accepted by normalization: scalar, array, or plain object.
 *
 * Depth-bounded to prevent combinatorial blowup during generation and
 * shrinking. At maxDepth 0 the generator falls back to scalars only.
 */
export function arbDeterministicValue(maxDepth = 2): fc.Arbitrary<unknown> {
  if (maxDepth <= 0) {
    return u(arbDeterministicScalar());
  }
  return fc.oneof(
    { weight: 4, arbitrary: u(arbDeterministicScalar()) },
    {
      weight: 1,
      arbitrary: u(
        fc.array(arbDeterministicValue(maxDepth - 1), { maxLength: 5 })
      ),
    },
    { weight: 1, arbitrary: u(arbDeterministicObject(maxDepth - 1)) }
  );
}

/**
 * Generates a plain object (Object.prototype) with:
 *   - non-empty string keys (never "__proto__" — see arbPojoWithProtoKey)
 *   - deterministic leaf values at nested levels
 *
 * "__proto__" is excluded from key generation to prevent the
 * Object.prototype.__proto__ setter from silently mutating the prototype
 * chain during fast-check's internal object construction via assignment.
 * Use arbPojoWithProtoKey to exercise the __proto__-as-own-property path.
 */
export function arbDeterministicObject(
  maxDepth = 2
): fc.Arbitrary<Record<string, unknown>> {
  return fc.dictionary(
    fc
      .string({ minLength: 1, maxLength: 16 })
      .filter((k: string) => k !== "__proto__"),
    arbDeterministicValue(maxDepth > 0 ? maxDepth - 1 : 0),
    { minKeys: 0, maxKeys: 6 }
  );
}

// ─── Proto-key object ─────────────────────────────────────────────────────────

/**
 * Generates a null-prototype object that includes "__proto__" as a genuine
 * own enumerable data property.
 *
 * Uses Object.create(null) so that the assignment `obj["__proto__"] = value`
 * stores the value as an own data property instead of invoking the
 * Object.prototype.__proto__ setter (which would silently change the
 * prototype and not create an own property at all).
 *
 * The resulting objects pass normalizeState / normalizeIntent's
 * isStrictPlainObject guard because it accepts null-prototype objects:
 *   Object.getPrototypeOf(obj) === null → true
 *
 * Object.keys() on a null-prototype object includes "__proto__" as a normal
 * own enumerable key, which is exactly the invariant the normalizers must
 * preserve in their output.
 */
export function arbPojoWithProtoKey(
  maxDepth = 1
): fc.Arbitrary<Record<string, unknown>> {
  return fc
    .tuple(arbDeterministicObject(maxDepth), arbDeterministicScalar())
    .map(
      ([base, protoVal]: [
        Record<string, unknown>,
        string | number | boolean | null,
      ]) => {
        // Null-prototype object: assigning "__proto__" creates an own data
        // property; there is no setter to intercept the write.
        const obj = Object.create(null) as Record<string, unknown>;
        for (const k of Object.keys(base)) {
          obj[k] = base[k];
        }
        // Assign after copying other keys; safe on null-prototype objects.
        obj["__proto__"] = protoVal;
        return obj;
      }
    );
}

// ─── Unsupported values ────────────────────────────────────────────────────────

/**
 * Generates values that normalization MUST reject.
 *
 * Covers all explicitly disallowed categories:
 *   - non-integer finite floats
 *   - NaN, +Infinity, -Infinity
 *   - undefined
 *   - bigint
 *   - symbol
 *   - function
 *   - Date, Map, Set, Buffer, Uint8Array (class instances / exotic objects)
 *
 * Use this arbitrary to drive fail-closed and no-coercion properties.
 */
export function arbUnsupportedValue(): fc.Arbitrary<unknown> {
  const nonIntegerFloat = fc
    .float({ noNaN: true, noDefaultInfinity: true })
    .filter((n: number) => !Number.isInteger(n));

  return fc.oneof(
    u(nonIntegerFloat),
    u(fc.constant(NaN)),
    u(fc.constant(Infinity)),
    u(fc.constant(-Infinity)),
    u(fc.constant(undefined)),
    u(fc.constant(new Date("2026-01-01T00:00:00.000Z"))),
    u(fc.constant(new Map<string, string>([["k", "v"]]))),
    u(fc.constant(new Set<number>([1, 2, 3]))),
    u(fc.bigInt()),
    u(fc.constant(function unsupportedFn() {})),
    u(fc.constant(Symbol("unsupported"))),
    u(fc.constant(Buffer.from("data"))),
    u(fc.constant(new Uint8Array([0, 1, 2])))
  );
}
