# OxDeAI Tests

This package mirrors the published test bundle and vendors `node_modules` so the invariants/fuzz fixtures can run offline and deterministically. To reclaim space locally, remove `tests/node_modules` and reinstall with `pnpm -C tests install` before running `pnpm -C tests test`.
