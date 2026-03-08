# Test Crypto Fixtures

TEST ONLY — DO NOT USE IN PRODUCTION.

This directory contains deterministic cryptographic fixtures used only by core test code.

Rules:

- Production private keys must never be committed.
- Fixtures in this directory are non-production and intentionally labeled.
- Keep fixture scope narrow; do not copy fixture private keys into runtime code.
