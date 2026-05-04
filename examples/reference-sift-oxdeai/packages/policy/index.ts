// SPDX-License-Identifier: Apache-2.0
/**
 * Policy rules for the reference deployment.
 *
 * In production, policy configuration is loaded from a signed manifest or
 * a configuration service. This reference implementation uses a static set
 * to keep the invariant code-level auditable.
 */

// ─── Known policies ───────────────────────────────────────────────────────────

/**
 * The set of policy IDs that this PEP accepts.
 * An AuthorizationV1 whose `policy_id` is NOT in this set is rejected,
 * even if the signature is valid.
 */
export const KNOWN_POLICIES = new Set([
  "transfer-policy-v1",
  "withdraw-policy-v1",
  "read-only-policy-v1",
]);

export function isKnownPolicy(policyId: string): boolean {
  return KNOWN_POLICIES.has(policyId);
}

// ─── Known issuers ────────────────────────────────────────────────────────────

/**
 * Accepted adapter issuers. An AuthorizationV1 whose `issuer` is NOT in
 * this set is rejected even if the signature is valid.
 */
export const KNOWN_ISSUERS = new Set(["adapter-issuer"]);

export function isKnownIssuer(issuer: string): boolean {
  return KNOWN_ISSUERS.has(issuer);
}
