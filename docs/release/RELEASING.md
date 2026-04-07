# Releasing OxDeAI Packages

## Status

Non-normative (developer documentation)






This repo uses **package-scoped tags only**. Legacy global tags like `vX.Y.Z` are historical and must not be used for new releases.

## Tag format

All new releases must use package-level tags:

- core-v1.7.0
- cli-v0.2.4
- sdk-v1.3.2
- guard-v1.0.2
- conformance-v1.5.0

Legacy global tags (vX.Y.Z) are deprecated and must not be used for new releases.

The following tags are currently classified as legacy / suspicious and should not be reused:
- adapters-v1.0.0
- adapters-v1.0.1

## Safe release flow

1) Bump the package version (e.g., `packages/core/package.json`).
2) Run checks (`pnpm lint`, `pnpm build`, `pnpm test` or targeted).
3) Commit the release changes.
4) Create the package tag: `git tag -a core-v1.7.0 -m "core v1.7.0"` (sign with `-s` if available).
5) Push commit + tag: `git push origin main core-v1.7.0`.
6) Publish the package (npm or internal registry as appropriate).
7) Create a GitHub release if desired, referencing the package tag.

## Tag hygiene

- Keep package tags matching the regex: `^(core|cli|conformance|guard|sdk)-v[0-9]+\.[0-9]+\.[0-9]+$`.
- Global tags `vX.Y.Z` are considered legacy; do not create new ones.
- For any other prefix (e.g., `adapters-v*`), treat as suspicious until a real package exists.
- Use `pnpm tags:audit` to review tags and `pnpm tags:cleanup:dry` for a safe cleanup plan before deleting anything.
