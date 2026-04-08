# Rust Verifier Skeleton (Reference)

Reference-only Rust starter for OxDeAI protocol verification.

This example is intentionally minimal and is **not** a normative implementation.
TypeScript (`@oxdeai/core`) remains the protocol reference implementation.

## Scope

This skeleton demonstrates verifier-first implementation shape:

- `types.rs` - protocol-facing artifact/result structs
- `canonical.rs` - canonical JSON + signing input construction
- `keyset.rs` - issuer/kid/alg key lookup
- `verify_authorization.rs` - fail-closed `AuthorizationV1` verification

## Why this exists

To help Rust implementers start with protocol-compatible verification before building a native decision engine.

## Run

The repo ships a minimal working pair for quick testing:

- `auth_case.json` - single AuthorizationV1
- `keyset.json` - matching Ed25519 public key

```bash
cd examples/rust-verifier
cargo run -- ./auth_case.json ./keyset.json pep-gateway.local
```

Expected outcomes:

- `ALLOW` when verification passes (the bundled case should ALLOW)
- `DENY` with explicit violation codes otherwise

## Notes

- Domain separator is fixed to `OXDEAI_AUTH_V1`.
- Signing input is `domain + "\n" + canonical_json(payload_without_signature)`.
- Verification is fail-closed on malformed payloads, unknown keys/algorithms, and signature mismatch.
