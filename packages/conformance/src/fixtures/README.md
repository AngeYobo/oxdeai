# Conformance Crypto Fixtures

TEST ONLY - DO NOT USE IN PRODUCTION.

This directory contains deterministic cryptographic fixtures used only for conformance vector generation/validation.

Rules:

- Production private keys must never be committed.
- Fixtures are allowed only in explicit fixture paths and must be labeled non-production.
- Deterministic fixtures should be minimized and isolated to test/conformance scope.
