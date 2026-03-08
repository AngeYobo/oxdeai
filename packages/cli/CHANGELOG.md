# Changelog

All notable changes to `@oxdeai/cli` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [0.2.0] - 2026-03-08

### Added

- Unified `verify` command support for:
  - `snapshot`
  - `audit`
  - `envelope`
  - `authorization`
- Support for authorization/envelope verification options:
  - expected issuer/audience/policy
  - trusted keyset input
  - signature verification requirement toggles
- Machine-readable and human-readable output paths with consistent command summaries.
- Dedicated CLI README with command surface, examples, and exit code contract.

### Changed

- Stabilized tooling command surface around:
  - `oxdeai build`
  - `oxdeai verify`
  - `oxdeai replay` (protocol-aware explicit stub)
- Normalized verification exit codes:
  - `0` = `ok`
  - `1` = `invalid` / malformed runtime failure
  - `2` = usage error
  - `3` = `inconclusive`
- Expanded CLI tests for authorization verification and malformed-input fail-closed behavior.

### Notes

- `@oxdeai/cli` is a tooling release line and is versioned independently from the protocol stack.
- Protocol compatibility claims are defined by:
  - `@oxdeai/core`
  - `@oxdeai/sdk`
  - `@oxdeai/conformance`
