# Changelog

All notable changes to `@oxdeai/sdk` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [1.3.2] - 2026-03-30

### Security

- `engine_secret` minimum-length and entropy requirements now enforced at runtime — insecure defaults removed.
- Timing-safe HMAC comparison (`timingSafeEqual`) applied in domain verification.

### Added

- Explicit verifier trust boundary with strict-mode enforcement in the trust model.
- DelegationV1 protocol artifact: full implementation, verification, and conformance vectors (139 assertions).

### Fixed

- `deepMerge` is now non-mutating; property-based tests added.
- `tool_limits` marked required in `State` type, aligning type with runtime behavior.
- PolicyEngine output types exported; decision-path property surfaced correctly.
- TypeScript type error for `engine_secret` resolved across examples and packages.
- Conformance vectors regenerated with 32-char secret and CI environment aligned.

### Changed

- Protocol-stack version alignment with:
  - `@oxdeai/core@1.6.1`
  - `@oxdeai/conformance@1.4.0`
- Trust boundary made explicit across SDK and documentation.

### Notes

- `@oxdeai/cli` remains on a separate tooling version line.

---

## [1.3.1] - 2026-03-08

### Changed

- Metadata-only packaging fix for npm consumers.
- Published dependency metadata now uses `@oxdeai/core@^1.3.0` directly (no workspace protocol spec in package metadata).

### Notes

- No runtime or protocol-semantics changes from `1.3.0`.

---

## [1.3.0] - 2026-03-08

### Added

- Stable public guard API for callback-boundary enforcement (`createGuard`).
- Guard-focused test coverage for allow/deny execution behavior and authorization enforcement.

### Changed

- SDK integration documentation updated for the v1.3 adoption layer.
- Protocol-stack version alignment with:
  - `@oxdeai/core@1.3.0`
  - `@oxdeai/conformance@1.3.0`

### Notes

- `@oxdeai/cli` remains on a separate tooling version line.
- No intentional protocol semantic break from `1.2.x`.

---

## [1.2.0] - 2026-03-08

### Added

- Protocol-stack alignment with OxDeAI non-forgeable verification milestone.
- SDK compatibility with AuthorizationV1 signature fields (`alg`, `kid`) and KeySet-based verification options surfaced from `@oxdeai/core`.

### Changed

- Integration flow documentation and examples aligned to the v1.2 protocol stack behavior.
- Client usage remains deterministic and protocol-compatible with stateless verification APIs.

### Notes

- `@oxdeai/sdk@1.2.0` is released together with:
  - `@oxdeai/core@1.2.0`
  - `@oxdeai/conformance@1.2.0`
- `@oxdeai/cli` remains on a separate tooling version line.
