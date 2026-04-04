# Non-Bypassable Demo (Minimal)

Architecture: `Agent -> PEP Gateway -> Protected Upstream`.

Invariant: no valid authorization → no execution path. The upstream refuses direct calls unless they carry the gateway-only secret.

## Files
- `protected-upstream.mjs` - protected target; enforces the internal executor token.
- `pep-gateway.mjs` - policy enforcement point; verifies authorization, intent hash, audience, expiry, and replay; forwards only on success.
- `agent.mjs` - simulates four scenarios.

## Run
```bash
# 1) export the shared secret (held only by gateway + upstream)
export UPSTREAM_EXECUTOR_TOKEN=demo-internal-token

# 2) start upstream (requires the env above)
node examples/non-bypassable-demo/protected-upstream.mjs

# 3) start gateway (requires the same env)
node examples/non-bypassable-demo/pep-gateway.mjs

# 4) run agent scenarios (agent never knows the token)
node examples/non-bypassable-demo/agent.mjs
```

Secret handling: the token lives only in the gateway and the protected upstream; the agent never reads or sends it. If `UPSTREAM_EXECUTOR_TOKEN` is missing, both upstream and gateway fail fast at startup.
