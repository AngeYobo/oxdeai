// SPDX-License-Identifier: Apache-2.0

/**
 * Property-based tests for normalizeIntent.
 *
 * Each property verifies an OxDeAI execution-boundary invariant:
 *   P1  Determinism          — same input always produces same output
 *   P2  Metadata exclusion   — intent exposes only type, tool, params
 *   P3  __proto__ own key    — preserved in params, prototype intact
 *   P4  Unsupported values   — fail closed without throwing
 *   P5  Floats               — always fail, never silently coerced
 *   P6  Invalid top-level    — non-plain-object params always fail
 *   P7  Action / tool match  — exact matching; mismatch returns known error code
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fc from "fast-check";

import {
  normalizeIntent,
  type NormalizeIntentResult,
} from "../src/normalizeIntent.js";
import type { SiftReceipt } from "../src/verifyReceipt.js";
import {
  arbDeterministicObject,
  arbDeterministicValue,
  arbPojoWithProtoKey,
  arbUnsupportedValue,
} from "./helpers/propertyArbitraries.js";

// ─── Run budget ───────────────────────────────────────────────────────────────

const RUNS = 200;

// ─── Baseline receipt ─────────────────────────────────────────────────────────

/**
 * Builds a structurally valid SiftReceipt for use as a stable test baseline.
 * normalizeIntent reads only receipt.action and receipt.tool, so the hash
 * and signature fields are intentionally placeholder values.
 */
function makeReceipt(overrides: Partial<SiftReceipt> = {}): SiftReceipt {
  return {
    receipt_version: "1.0",
    tenant_id: "tenant-test",
    agent_id: "agent-test",
    action: "transfer_funds",
    tool: "payments_api",
    decision: "ALLOW",
    risk_tier: 1,
    timestamp: "2026-04-14T12:00:00.000Z",
    nonce: "11111111-1111-1111-1111-111111111111",
    policy_matched: "payments-policy-v1",
    receipt_hash: "sha256:" + "a".repeat(64),
    signature: "base64-signature-placeholder",
    ...overrides,
  };
}

// Receipt governance fields that must never appear in normalized intent output.
const RECEIPT_METADATA_KEYS: ReadonlyArray<keyof SiftReceipt> = [
  "tenant_id",
  "agent_id",
  "timestamp",
  "nonce",
  "receipt_hash",
  "signature",
  "policy_matched",
  "risk_tier",
  "decision",
];

// ─── P1. Determinism ──────────────────────────────────────────────────────────

test("P1: normalizeIntent is deterministic — same inputs always produce the same output", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbDeterministicObject(),
      (params: Record<string, unknown>) => {
        const r1 = normalizeIntent({ receipt, params });
        const r2 = normalizeIntent({ receipt, params });
        assert.deepStrictEqual(r1, r2);
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P2. Receipt metadata exclusion ──────────────────────────────────────────

test("P2: normalized intent contains only type, tool, and params — no receipt metadata at any level", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbDeterministicObject(),
      (params: Record<string, unknown>) => {
        const result = normalizeIntent({ receipt, params });

        assert.equal(
          result.ok,
          true,
          "normalization must succeed for deterministic params"
        );
        if (!result.ok) return;

        // Exactly three top-level keys — no extras.
        const intentKeys = Object.keys(result.intent).sort();
        assert.deepStrictEqual(
          intentKeys,
          ["params", "tool", "type"],
          "intent must have exactly the keys: type, tool, params"
        );

        // No receipt governance field must appear at the intent's top level.
        for (const metaKey of RECEIPT_METADATA_KEYS) {
          assert.equal(
            Object.prototype.hasOwnProperty.call(result.intent, metaKey),
            false,
            `intent must not expose receipt governance field: ${metaKey}`
          );
        }

        // Structural invariants on the fixed fields.
        assert.equal(result.intent.type, "EXECUTE");
        // tool must be sourced from receipt.tool — not invented or substituted.
        assert.equal(
          result.intent.tool,
          receipt.tool,
          "intent.tool must equal receipt.tool"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P3. __proto__ own key preservation in params ────────────────────────────

test("P3: normalizeIntent preserves __proto__ as own data property in params and never mutates the prototype chain", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbPojoWithProtoKey(),
      (params: Record<string, unknown>) => {
        const protoValBefore = params["__proto__"];

        const result = normalizeIntent({ receipt, params });

        assert.equal(
          result.ok,
          true,
          "normalization must succeed for params containing __proto__ as own key"
        );
        if (!result.ok) return;

        // __proto__ must survive as an own enumerable property on normalized params.
        assert.equal(
          Object.prototype.hasOwnProperty.call(result.intent.params, "__proto__"),
          true,
          "__proto__ must be an own property of the normalized params object"
        );

        // The stored value must be identical to what was supplied.
        assert.deepStrictEqual(
          result.intent.params["__proto__"],
          protoValBefore,
          "__proto__ value must be preserved without modification"
        );

        // Normalized params are always Object.create(null); the prototype must
        // never be changed regardless of the input key names.
        assert.equal(
          Object.getPrototypeOf(result.intent.params),
          null,
          "normalized params prototype must be null — __proto__ key must not mutate the prototype chain"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P4. Unsupported values fail closed ───────────────────────────────────────

test("P4: normalizeIntent fails closed on unsupported values nested in params — never throws", () => {
  const receipt = makeReceipt();

  // Wrap the unsupported value as a field so the failure comes from recursive
  // value validation, not from the top-level params shape guard (P6).
  const arbParamsWithUnsupportedNested = fc
    .tuple(
      fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => k !== "__proto__"),
      arbUnsupportedValue()
    )
    .map(([key, badVal]: [string, unknown]) => ({ [key]: badVal }));

  fc.assert(
    fc.property(
      arbParamsWithUnsupportedNested,
      (params: Record<string, unknown>) => {
        let result: NormalizeIntentResult;
        try {
          result = normalizeIntent({ receipt, params });
        } catch (e) {
          assert.fail(
            `normalizeIntent threw instead of returning { ok: false }: ${String(e)}`
          );
          return;
        }
        assert.equal(
          result.ok,
          false,
          "normalization must return { ok: false } for params containing an unsupported nested value"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P5. Floats always fail ───────────────────────────────────────────────────

test("P5: non-integer finite floats anywhere in params always cause normalization to fail", () => {
  const receipt = makeReceipt();

  const nonIntegerFloat = fc
    .float({ noNaN: true, noDefaultInfinity: true })
    .filter((n: number) => !Number.isInteger(n));

  const arbParamsWithFloat = fc
    .tuple(
      fc
        .string({ minLength: 1, maxLength: 16 })
        .filter((k: string) => k !== "__proto__"),
      nonIntegerFloat
    )
    .map(([key, floatVal]: [string, number]) => ({ [key]: floatVal }));

  fc.assert(
    fc.property(
      arbParamsWithFloat,
      (params: Record<string, unknown>) => {
        const result = normalizeIntent({ receipt, params });
        assert.equal(
          result.ok,
          false,
          "params containing a float must not normalize successfully — floats are never silently coerced"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ─── P6. Top-level params must be strict plain object ────────────────────────

test("P6: non-plain-object top-level params always fail (null, undefined, array, primitives)", () => {
  const receipt = makeReceipt();

  const arbInvalidParams: fc.Arbitrary<unknown> = fc.oneof(
    fc.constant(null),
    fc.constant(undefined),
    fc.array(arbDeterministicValue(1), { maxLength: 5 }),
    fc.string({ minLength: 0, maxLength: 32 }),
    fc.integer({ min: -100_000, max: 100_000 }),
    fc.boolean()
  );

  fc.assert(
    fc.property(arbInvalidParams, (invalidParams: unknown) => {
      let result: NormalizeIntentResult;
      try {
        result = normalizeIntent({ receipt, params: invalidParams });
      } catch (e) {
        assert.fail(
          `normalizeIntent threw on invalid top-level params instead of returning { ok: false }: ${String(e)}`
        );
        return;
      }
      assert.equal(
        result.ok,
        false,
        "normalization must fail for any non-plain-object top-level params"
      );
    }),
    { numRuns: RUNS }
  );
});

// ─── P7. expectedAction / expectedTool exact matching ────────────────────────

test("P7a: matching expectedAction and expectedTool both succeed", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbDeterministicObject(),
      (params: Record<string, unknown>) => {
        const result = normalizeIntent({
          receipt,
          params,
          expectedAction: receipt.action,
          expectedTool: receipt.tool,
        });
        assert.equal(
          result.ok,
          true,
          "normalizeIntent must succeed when expectedAction and expectedTool match the receipt"
        );
      }
    ),
    { numRuns: RUNS }
  );
});

test("P7b: mismatched expectedAction fails with ACTION_MISMATCH", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbDeterministicObject(),
      fc
        .string({ minLength: 1, maxLength: 32 })
        .filter((s: string) => s !== receipt.action),
      (params: Record<string, unknown>, wrongAction: string) => {
        const result = normalizeIntent({
          receipt,
          params,
          expectedAction: wrongAction,
        });

        assert.equal(
          result.ok,
          false,
          "normalizeIntent must fail when expectedAction does not match the receipt action"
        );
        if (!result.ok) {
          assert.equal(
            result.code,
            "ACTION_MISMATCH",
            "error code must be ACTION_MISMATCH for action mismatch"
          );
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("P7c: mismatched expectedTool fails with TOOL_MISMATCH", () => {
  const receipt = makeReceipt();

  fc.assert(
    fc.property(
      arbDeterministicObject(),
      fc
        .string({ minLength: 1, maxLength: 32 })
        .filter((s: string) => s !== receipt.tool),
      (params: Record<string, unknown>, wrongTool: string) => {
        const result = normalizeIntent({
          receipt,
          params,
          expectedTool: wrongTool,
        });

        assert.equal(
          result.ok,
          false,
          "normalizeIntent must fail when expectedTool does not match the receipt tool"
        );
        if (!result.ok) {
          assert.equal(
            result.code,
            "TOOL_MISMATCH",
            "error code must be TOOL_MISMATCH for tool mismatch"
          );
        }
      }
    ),
    { numRuns: RUNS }
  );
});
