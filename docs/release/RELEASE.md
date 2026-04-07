# OxDeAI Release Policy

## Status

Non-normative (developer documentation)






Last updated: 2026-03-19

This document is the single source of truth for OxDeAI release governance and release execution.

## 1. Scope

This policy covers:

- protocol specifications and artifacts
- release governance for published packages
- versioning rules and breaking-change boundaries
- release workflow, tagging, and provenance
- validation and publication checks

Audience: maintainers, contributors, and auditors.

## 2. Package Groups

Protocol stack packages (coordinated releases):

- `@oxdeai/core`
- `@oxdeai/sdk`
- `@oxdeai/conformance`

Adapter packages (coordinated, independent version line from protocol stack):

- `@oxdeai/guard`
- `@oxdeai/langgraph`
- `@oxdeai/openai-agents`
- `@oxdeai/crewai`
- `@oxdeai/autogen`
- `@oxdeai/openclaw`

Tooling package (independent release line):

- `@oxdeai/cli`

Non-release packages for protocol versioning:

- examples (for example `examples/openai-tools`, `examples/langgraph`)
- internal tests (for example `@oxdeai/tests`)

Examples and internal tests do not define protocol release status.

## 3. Versioning Policy

- The protocol stack (`core`, `sdk`, `conformance`) MUST move on a shared version line.
- Protocol milestones and compatibility claims MUST map to the shared protocol stack version.
- `@oxdeai/cli` MAY release independently until declared stable under the protocol-stack line.
- Examples/tests MUST NOT be used as authoritative protocol version indicators.

## 4. SemVer Rules (Protocol Stack)

### Patch (`1.0.x`)

- MUST be backward compatible with prior `1.0.y`.
- MUST NOT change protocol semantics:
  - canonicalization
  - hashing/signature binding
  - envelope `formatVersion` behavior
  - verification result semantics
- MAY include:
  - documentation clarifications
  - schema validation tightening aligned to existing behavior
  - CI/tooling hardening
  - non-breaking fixes

### Minor (`1.x.0`, `x > 0`)

- Adds backward-compatible capabilities.
- MUST preserve stable protocol artifacts from `1.0.0`.

### Major (`2.0.0+`)

- Required for breaking protocol/API changes.

## 5. What Is Breaking

The following require a major release:

- Changing `VerificationResult` in a non-backward-compatible way
- Changing `VerificationEnvelopeV1` wire semantics
- Changing violation-code semantics used by stateless verifiers
- Changing canonical hashing behavior for stable artifacts
- Removing/renaming documented public API symbols

## 6. Tagging Policy

- Coordinated protocol stack releases MUST use repo tags `vX.Y.Z`.
- Tags MUST point to the exact commit used for publication.
- Package-specific tags are discouraged for coordinated protocol releases.
- Tooling-only releases SHOULD use package-scoped tags to avoid protocol-tag ambiguity (for example `cli-v0.2.0`).
- If package-specific tags are introduced, mapping rules to protocol tags MUST be documented first.

## 7. Changelog Requirements

Every protocol stack release MUST be documented in:

- `packages/core/CHANGELOG.md`
- `packages/sdk/CHANGELOG.md`
- `packages/conformance/CHANGELOG.md`

Release notes MUST map npm versions to Git history (commit/tag references).

## 8. Required Validation Gates

All required gates MUST pass before protocol tagging/publication:

1. `pnpm install --frozen-lockfile`
2. `pnpm build`
3. `pnpm test`
4. `pnpm -C packages/core api:check`
5. `pnpm -C packages/core api:fingerprint:check`
6. `pnpm -C packages/conformance validate`
7. Demo smoke checks when affected

## 9. API Report / Fingerprint Baseline

Update API baselines only when API change is intentional and reviewed.

1. Run:
   - `pnpm -C packages/core api:report`
   - `pnpm -C packages/core api:fingerprint`
2. Review diffs:
   - `packages/core/temp/core.api.md`
   - `packages/core/etc/core.api.md`
   - `packages/core/API_FINGERPRINT`
3. If approved, update baselines in the same PR with rationale.
4. Re-run `api:check` and `api:fingerprint:check`.

## 10. Release Workflow (Protocol Stack)

1. Ensure clean working tree.
2. Bump `core`, `sdk`, and `conformance` to one target version.
3. Update changelogs and release notes.
4. Run required validation gates.
5. Commit release changes.
6. Create/push coordinated tag (`vX.Y.Z`).
7. Publish packages in order:
   - `@oxdeai/core`
   - `@oxdeai/sdk`
   - `@oxdeai/conformance`
8. Verify published npm versions.

If publication fails, resolve and retry from the same committed state, or cut a new patch release with explicit notes.

## 11. Security and Provenance

- npm publication is immutable; Git tags/commits provide provenance context.
- Published versions MUST correspond to committed and tagged repository state.
- Post-release fixes MUST ship as new versions; published versions MUST NOT be rewritten.
- Follow coordinated disclosure process in [SECURITY.md](../security/SECURITY.md).
- Release notes MUST mention security-relevant changes.
- Test signing material MUST be explicitly test-only and non-production.

## 12. Future Evolution

Shared protocol-stack versioning is the current model.

If protocol package cadence diverges significantly, maintainers MAY adopt a new model. Any change MUST be documented here before use.
