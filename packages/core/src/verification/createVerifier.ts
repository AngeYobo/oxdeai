// SPDX-License-Identifier: Apache-2.0
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";
import type { VerificationResult, VerifyEnvelopeOptions } from "./types.js";
import type { VerifyAuthorizationOptions } from "./verifyAuthorization.js";
import { verifyAuthorization } from "./verifyAuthorization.js";
import { verifyEnvelope } from "./verifyEnvelope.js";

/** @public */
export type VerifierConfig = {
  /** Required. Defines the trust boundary: only artifacts from issuers present in these
   *  keysets will be accepted. An empty array is rejected at construction time. */
  trustedKeySets: KeySet[];
  /** Optional issuer constraint applied to all verifications unless overridden per call. */
  expectedIssuer?: string;
};

type BoundAuthOptions   = Omit<VerifyAuthorizationOptions, "trustedKeySets" | "mode">;
type BoundEnvelopeOptions = Omit<VerifyEnvelopeOptions,    "trustedKeySets" | "mode">;

/** @public */
export type BoundVerifier = {
  verifyAuthorization(auth: AuthorizationV1,   opts?: BoundAuthOptions):    VerificationResult;
  verifyEnvelope(envelopeBytes: Uint8Array,    opts?: BoundEnvelopeOptions): VerificationResult;
};

/**
 * Creates a trust-configured verifier.
 *
 * `trustedKeySets` is required and must be non-empty — it is the trust boundary.
 * All verifications run in strict mode: missing trust configuration is a hard failure,
 * not a warning.
 *
 * Use this instead of calling `verifyAuthorization` / `verifyEnvelope` directly when
 * you need the type system to enforce that trust is configured before verification.
 *
 * @public
 */
export function createVerifier(config: VerifierConfig): BoundVerifier {
  if (config.trustedKeySets.length === 0) {
    throw new Error(
      "createVerifier: trustedKeySets must not be empty — " +
      "provide at least one KeySet to establish a trust boundary"
    );
  }

  return {
    verifyAuthorization(auth, opts) {
      return verifyAuthorization(auth, {
        ...opts,
        mode: "strict",
        trustedKeySets: config.trustedKeySets,
        expectedIssuer: opts?.expectedIssuer ?? config.expectedIssuer,
      });
    },

    verifyEnvelope(envelopeBytes, opts) {
      return verifyEnvelope(envelopeBytes, {
        ...opts,
        mode: "strict",
        trustedKeySets: config.trustedKeySets,
        expectedIssuer: opts?.expectedIssuer ?? config.expectedIssuer,
      });
    },
  };
}
