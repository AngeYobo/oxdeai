# Changelog

All notable changes to `@oxdeai/conformance` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [1.3.0] - 2026-03-08

### Changed

- Protocol-stack release alignment to the v1.3 line with synchronized versioning.
- Conformance package publication metadata updated to target `@oxdeai/core@^1.3.0`.

### Notes

- `@oxdeai/conformance@1.3.0` is released together with:
  - `@oxdeai/core@1.3.0`
  - `@oxdeai/sdk@1.3.0`
- Validator behavior and vector semantics remain aligned with the existing deterministic protocol guarantees from `1.2.x`.

---

## [1.2.0] - 2026-03-08

### Added

- Protocol milestone vectors for non-forgeable verification.
- Authorization signature verification coverage (Ed25519, `alg`, `kid`, tamper/unknown-key/unknown-alg cases).
- Envelope signature verification coverage with deterministic fail-closed outcomes.

### Changed

- Validator alignment with `verifyAuthorization(...)` and enhanced `verifyEnvelope(...)` behaviors.
- Deterministic conformance output expanded for v1.2 protocol-stack verification paths.

### Notes

- `@oxdeai/conformance@1.2.0` is released together with:
  - `@oxdeai/core@1.2.0`
  - `@oxdeai/sdk@1.2.0`
- `@oxdeai/cli` remains on a separate tooling version line.
