# Changelog

All notable changes to `@oxdeai/guard` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [1.0.2] - 2026-03-20

### Added

- DelegationV1 enforcement integrated into the PEP boundary.
- Full delegation chain verification before execution: parent hash binding, scope narrowing (tools, max_amount), expiry ceiling, delegator identity, policy binding.
- `GuardDelegationInput` type (`delegation` + `parentAuth`) for child-agent execution path.
- `GuardCallOptions` — optional third argument to the guard function; supports `delegation` for the delegation path.
- `OxDeAIDelegationError` — thrown on any delegation chain violation; `execute` is never called.
- `trustedKeySets` and `requireDelegationSignatureVerification` config options for Ed25519 signature enforcement on delegation artifacts.
- `consumedDelegationIds` config option for replay protection on the delegation path.
- TOCTOU, determinism, and enforcement-boundary test coverage (G-D1–G-D3 property tests).

### Notes

- `setState` is not called on the delegation path — the parent authorization's state is authoritative.
- Protocol stack alignment: `@oxdeai/core@1.5.0`.

---

## [1.0.1] - 2026-03-16

### Changed

- Apache-2.0 license added to package metadata.
- External documentation links changed from relative to absolute GitHub URLs.
- Protocol stack alignment with `@oxdeai/core@1.5.0`.

---

## [1.0.0] - 2026-03-15

### Added

- Initial release of `@oxdeai/guard` — universal Policy Enforcement Point (PEP) for the OxDeAI ecosystem.
- `OxDeAIGuard` factory: runtime-agnostic guard function enforcing authorization before any tool execution.
- Fail-closed security invariants: DENY throws `OxDeAIDenyError`; missing/invalid authorization throws `OxDeAIAuthorizationError`; normalization failure throws `OxDeAINormalizationError`.
- Default action normalizer (`defaultNormalizeAction`) mapping `ProposedAction` fields to `Intent`.
- `mapActionToIntent` hook for custom domain-specific intent mapping.
- `beforeExecute` and `onDecision` lifecycle hooks for auditing and observability.
- `strict` mode flag for hard failure on missing optional fields.
- Protocol stack alignment: `@oxdeai/core@1.3.x`.
