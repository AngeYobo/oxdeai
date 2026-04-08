# Non-bypassable Execution Boundary - OpenClaw

## Status
Non-normative (developer demo)

## What it shows
- OpenClaw agent calls the PEP Gateway.
- Gateway enforces ALLOW / DENY / REPLAY.
- Direct upstream call (no token) returns 403.
- No valid authorization → no execution path.

## Run
Prereqs: Node 20+, pnpm 9+, repo deps installed.

```bash
export UPSTREAM_EXECUTOR_TOKEN=demo-internal-token

pnpm -C examples/non-bypassable-openclaw upstream &
pnpm -C examples/non-bypassable-openclaw gateway &
sleep 2
pnpm -C examples/non-bypassable-openclaw agent
```

Expected:

* ALLOW → executed (intent hash matches)
* DENY_HASH_MISMATCH → blocked (intent hash mismatch)
* REPLAY → blocked (auth_id reused)
* BYPASS → rejected (403, no internal token)


## Notes
- Reuses the existing protected upstream and PEP gateway; only the agent side is OpenClaw-driven.
- Uses native `fetch` when available (falls back to `node-fetch` lazily if needed).
- Authorization uses gateway-matching canonicalization to compute `intent_hash` for the ALLOW path.
