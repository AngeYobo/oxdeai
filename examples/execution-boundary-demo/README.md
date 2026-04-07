# Execution Boundary Demo (OxDeAI)

## Status

Non-normative (developer documentation)

## What this demo shows

Two-panel UI that contrasts:
- **Unprotected path** – action executes without verification.
- **Protected path** – action must carry a valid `AuthorizationV1`; otherwise execution is blocked (fail-closed).

Core invariant:  
`No valid authorization → no execution path`

## Run the demo

Prereqs: Node.js 20+, pnpm 9+, repo dependencies installed (`pnpm install` at repo root).

From repo root:

```bash
pnpm -C examples/execution-boundary-demo start
```

Then open the URL printed by the server (defaults to http://localhost:3001).

## Terminal-only variant

If you want a headless run that prints the protected vs unprotected outcomes:

```bash
pnpm -C examples/execution-boundary-demo terminal
```

## How it works (brief)

The server uses `@oxdeai/core` for deterministic authorization and `@oxdeai/guard` as the Policy Enforcement Point (PEP). The protected path verifies an `AuthorizationV1` artifact before allowing the side effect; the unprotected path bypasses the PEP to illustrate the risk.
