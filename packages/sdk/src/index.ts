/**
 * OxDeAI SDK — integration layer on top of @oxdeai/core.
 *
 * For PEP-side verification of externally issued authorization artifacts, use
 * `createVerifier` (re-exported from @oxdeai/core below) with explicit `trustedKeySets`.
 * In strict mode, verification fails closed when `trustedKeySets` is not configured
 * (`TRUSTED_KEYSETS_REQUIRED`). A cryptographically valid artifact is not trusted by
 * default — trust is configured explicitly by the verifier.
 */
export * from "@oxdeai/core";
export * from "./types.js";
export * from "./builders.js";
export * from "./adapters.js";
export * from "./client.js";
export * from "./guard.js";
