// SPDX-License-Identifier: Apache-2.0
/** @public */
export type DelegationScope = {
  tools?: string[];
  max_amount?: bigint;
  max_actions?: number;
  max_depth?: number;
};

/**
 * DelegationV1 — a strictly narrowing, single-hop, locally verifiable
 * delegation artifact derived from a parent AuthorizationV1.
 *
 * @public
 */
export type DelegationV1 = {
  delegation_id: string;
  issuer: string;
  audience: string;
  parent_auth_hash: string; // sha256 hex of canonical parent AuthorizationV1
  delegator: string;        // MUST match parent.audience
  delegatee: string;        // agent receiving delegated authority
  scope: DelegationScope;
  policy_id: string;        // MUST match parent.policy_id
  issued_at: number;        // unix seconds
  expiry: number;           // unix seconds, MUST be <= parent.expiry
  alg: "Ed25519";
  kid: string;
  signature: string;        // base64 Ed25519 over canonical signing input
};
