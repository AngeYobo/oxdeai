// SPDX-License-Identifier: Apache-2.0
/** @public */
export type SignatureAlgorithm = "Ed25519" | "HMAC-SHA256";

/** @public */
export type KeyStatus = "active" | "retired" | "revoked";

/** @public */
export type KeySetKey = {
  kid: string;
  alg: SignatureAlgorithm;
  public_key: string; // PEM-encoded public key
  status?: KeyStatus;
  not_before?: number; // unix seconds
  not_after?: number; // unix seconds
};

/** @public */
export type KeySet = {
  issuer: string;
  version: string;
  keys: KeySetKey[];
};
