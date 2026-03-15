import { createHash, randomBytes } from "node:crypto";
import type { ActionType, Intent } from "@oxdeai/core";
import type { ProposedAction } from "./types.js";
import { OxDeAINormalizationError } from "./errors.js";

/**
 * Map a ProposedAction name or resourceType to one of the four canonical ActionTypes.
 *
 * Precedence: resourceType → name → "PROVISION" (safe default for infrastructure).
 */
function inferActionType(name: string, resourceType?: string): ActionType {
  const needle = (resourceType ?? name).toLowerCase();
  // Check ONCHAIN_TX first — "onchain_transfer" must not be mistaken for PAYMENT.
  if (needle.includes("onchain") || needle.includes("blockchain") || needle.includes("chain") || needle.includes("mint") || needle.includes("swap")) {
    return "ONCHAIN_TX";
  }
  if (needle.includes("payment") || needle.includes("pay") || needle.includes("transfer") || needle.includes("send")) {
    return "PAYMENT";
  }
  if (needle.includes("purchase") || needle.includes("buy") || needle.includes("order") || needle.includes("subscribe")) {
    return "PURCHASE";
  }
  return "PROVISION";
}

/**
 * Compute a SHA-256 hex digest of the action args for use as metadata_hash.
 * Sorted keys ensure determinism regardless of arg insertion order.
 */
function hashArgs(args: Record<string, unknown>): string {
  const sorted = Object.fromEntries(
    Object.keys(args)
      .sort()
      .map((k) => [k, args[k]])
  );
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}

/**
 * Extract a required string field from the action context.
 * Throws OxDeAINormalizationError when the field is absent or not a string.
 */
function requireContextString(context: Record<string, unknown> | undefined, field: string): string {
  const value = context?.[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new OxDeAINormalizationError(
      `ProposedAction.context.${field} is required for default normalization but was not provided or is not a non-empty string. ` +
      `Supply it via action.context.${field} or provide a custom mapActionToIntent function.`
    );
  }
  return value;
}

/**
 * Default normalizer: converts a ProposedAction to an OxDeAI-compatible Intent.
 *
 * Required fields (must be present in action.context):
 *   - agent_id: string  — identity of the acting agent
 *
 * Optional fields with safe defaults:
 *   - context.intent_id   — random UUID generated if absent
 *   - context.target      — defaults to action.name
 *   - context.nonce       — random bigint generated if absent
 *   - estimatedCost       — defaults to 0 (amount = 0n)
 *   - timestampSeconds    — defaults to current unix second
 *   - resourceType        — used to infer action_type from action.name if absent
 *
 * Throws OxDeAINormalizationError on any missing required field.
 * Never throws a generic Error — callers can distinguish normalization failures.
 */
export function defaultNormalizeAction(action: ProposedAction): Intent {
  if (!action || typeof action.name !== "string" || action.name.length === 0) {
    throw new OxDeAINormalizationError("ProposedAction.name must be a non-empty string.");
  }
  if (typeof action.args !== "object" || action.args === null || Array.isArray(action.args)) {
    throw new OxDeAINormalizationError("ProposedAction.args must be a plain object.");
  }

  const agent_id = requireContextString(action.context, "agent_id");

  const intent_id: string =
    typeof action.context?.intent_id === "string" && action.context.intent_id.length > 0
      ? action.context.intent_id
      : randomBytes(16).toString("hex");

  const target: string =
    typeof action.context?.target === "string" && action.context.target.length > 0
      ? action.context.target
      : action.name;

  const rawNonce = action.context?.nonce;
  const nonce: bigint =
    typeof rawNonce === "bigint"
      ? rawNonce
      : typeof rawNonce === "number"
      ? BigInt(Math.trunc(rawNonce))
      : typeof rawNonce === "string"
      ? BigInt(rawNonce)
      : BigInt("0x" + randomBytes(8).toString("hex"));

  // estimatedCost is in whole units; store as fixed-point with 6 decimal places.
  const costUnits = action.estimatedCost ?? 0;
  if (!Number.isFinite(costUnits) || costUnits < 0) {
    throw new OxDeAINormalizationError(
      `ProposedAction.estimatedCost must be a non-negative finite number, got: ${costUnits}`
    );
  }
  const amount = BigInt(Math.round(costUnits * 1_000_000));

  const timestamp =
    typeof action.timestampSeconds === "number" && Number.isFinite(action.timestampSeconds)
      ? Math.trunc(action.timestampSeconds)
      : Math.floor(Date.now() / 1000);

  const action_type = inferActionType(action.name, action.resourceType);
  const metadata_hash = hashArgs(action.args);

  return {
    type: "EXECUTE",
    intent_id,
    agent_id,
    action_type,
    amount,
    target,
    timestamp,
    metadata_hash,
    nonce,
    signature: "oxdeai-guard-placeholder",
  };
}
