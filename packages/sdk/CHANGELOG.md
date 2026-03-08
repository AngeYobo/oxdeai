# Changelog

All notable changes to `@oxdeai/sdk` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

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
