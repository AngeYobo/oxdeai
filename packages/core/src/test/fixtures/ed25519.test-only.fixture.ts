/**
 * TEST ONLY — DO NOT USE IN PRODUCTION.
 *
 * Deterministic Ed25519 fixture for core test cases.
 * This keypair is intentionally non-secret and must never be reused for real signing.
 */

export const TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBx0hBPi6cIYPo/JZbavNXDDLlfV1vj+IyS+R4oq2Zvx
-----END PRIVATE KEY-----`;

export const TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWiMMGTYK7zzHwZXLzDpCshxAH6Lgx8gVsJaixePuY7g=
-----END PUBLIC KEY-----`;
