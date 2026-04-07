# Delegation Demo (OxDeAI)

## Status

Non-normative (developer documentation)

## What this demo shows

Two-panel UI illustrating delegated authority without scope amplification:
- **Parent AuthorizationV1** grants base capability.
- **DelegationV1** narrows scope to the delegatee (single-hop, no widening).
- Protected path enforces the delegation chain; out-of-scope actions are denied (fail-closed).

Core invariant:  
`No valid authorization → no execution path`

## Run the demo

Prereqs: Node.js 20+, pnpm 9+, repo dependencies installed (`pnpm install` at repo root).

From repo root:

```bash
pnpm -C examples/delegation-demo start
```

Then open the URL printed by the server (defaults to http://localhost:3002).

## Terminal-only variant

If you want a headless run that prints allowed vs denied delegated actions:

```bash
pnpm -C examples/delegation-demo terminal
```

## How it works (brief)

The server uses `@oxdeai/core` and `@oxdeai/guard` to verify a parent `AuthorizationV1` and a child `DelegationV1`. The PEP enforces single-hop, narrowing-only delegation before executing the side effect; any scope widening or delegatee mismatch is blocked.
