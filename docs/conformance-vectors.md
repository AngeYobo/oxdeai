# Conformance Vectors Index

This index helps non-TypeScript implementers choose where to start in `packages/conformance/vectors`.

## Core Vector Categories

- `authorization-verification.json`: authorization verification status and violations
- `authorization-signature-verification.json`: signature-specific authorization checks
- `snapshot-hash.json`: canonical snapshot encoding/hash expectations
- `audit-chain.json`: deterministic audit hash-chain behavior
- `envelope-verification.json`: envelope verification outcomes
- `envelope-signature-verification.json`: envelope signature verification behavior

## Suggested Start Order

1. `snapshot-hash.json`
2. `authorization-verification.json`
3. `authorization-signature-verification.json`
4. `audit-chain.json`
5. `envelope-verification.json`
6. `envelope-signature-verification.json`

Passing all relevant vectors indicates behavioral alignment with the protocol profile for the selected version line.
