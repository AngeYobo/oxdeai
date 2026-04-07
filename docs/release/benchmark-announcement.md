# OxDeAI Benchmark Announcement

## Status

Non-normative (developer documentation)






OxDeAI now includes a reproducible benchmark suite for measuring the runtime cost of its authorization boundary.

The most important result from the latest full-suite local run is straightforward:

- single-worker protected execution added about `+14.8 us p50` / `+21.8 us mean` in `best-effort` mode
- single-worker protected execution added about `+16.6 us p50` / `+25.2 us mean` in `strict` mode

These figures are measured as:

`protectedPath - baselinePath`

on the run recorded in:

- `bench/outputs/run-2026-03-11-12-25-55.json`

This is the practical performance result to pay attention to. OxDeAI provides deterministic authorization for agent actions with tens-of-microseconds inline overhead on the tested machine.

## Why this benchmark exists

For an agent runtime, the relevant engineering question is not whether a verifier is fast in isolation. The relevant question is whether a pre-execution authorization boundary can be enforced without materially changing runtime behavior.

OxDeAI is designed around that boundary:

- the runtime proposes an action
- OxDeAI evaluates policy deterministically
- an authorization artifact is emitted only on `ALLOW`
- the relying party verifies authorization before the side effect executes

That gives a fail-closed execution model for actions such as:

- tool calls
- external API calls
- payments
- provisioning operations

The benchmark exists to measure the practical cost of that boundary.

## What the suite measures

The benchmark reports four main scenarios:

- `evaluate`
- `verifyEnvelope`
- `baselinePath`
- `protectedPath`

These are the most useful scenarios for adoption decisions:

- `evaluate` isolates policy decision cost
- `verifyEnvelope` isolates envelope verification cost
- `baselinePath` provides a no-authorization comparison path
- `protectedPath` shows the actual inline cost of enforcing the boundary

`verifyAuthorization` is still measured in the suite, but it is treated as a secondary diagnostic result because its standalone latency is often close to the measurement noise floor relative to the end-to-end protected path.

## Latest measured result

Environment for the latest full-suite run:

- CPU: Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz
- logical cores: 4
- runtime: Node.js v22.9.0
- OS: Linux 5.15.133.1-microsoft-standard-WSL2 x64
- environment: WSL2

Benchmark configuration:

- `--scenario=all`
- `--runs=5`
- `--iterations=100000`
- `--warmup=10000`
- `--concurrency=1,4`
- `--envelopeMode=both`

Selected single-worker results:

| Scenario | p50 (us) | p95 (us) | p99 (us) | mean (us) |
|---|---:|---:|---:|---:|
| `evaluate` | 23.833 | 37.501 | 64.520 | 29.956 |
| `verifyEnvelope` (`best-effort`) | 15.457 | 21.654 | 45.956 | 17.199 |
| `verifyEnvelope` (`strict`) | 15.546 | 22.307 | 46.339 | 17.140 |
| `baselinePath` | 8.495 | 8.891 | 23.077 | 8.993 |
| `protectedPath` (`best-effort`) | 23.326 | 37.275 | 69.070 | 30.843 |
| `protectedPath` (`strict`) | 25.075 | 40.306 | 77.067 | 34.208 |

Absolute single-worker overhead:

| Protected mode | Delta p50 (us) | Delta p95 (us) | Delta p99 (us) | Delta mean (us) |
|---|---:|---:|---:|---:|
| `best-effort` | 14.831 | 28.384 | 45.993 | 21.850 |
| `strict` | 16.580 | 31.415 | 53.990 | 25.215 |

## Interpretation

The result is not that authorization is “free.” The result is that a deterministic fail-closed authorization boundary can be inserted into an agent execution path with bounded microsecond-scale overhead on the tested host.

For many agent systems, that overhead is small relative to the latency of the protected side effect itself, which is often dominated by:

- network I/O
- model calls
- database writes
- queueing
- external tool execution

This makes the benchmark useful for systems design decisions. It shows that the authorization boundary is cheap enough to be practical while still being explicit and reproducible.

## Reproducibility

The benchmark is included in the repository and is intended to be rerun.

Run the full suite locally with:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both
```

Important caveats:

- results depend on CPU, runtime, and scheduler behavior
- WSL, VMs, laptops, and shared hosts usually increase noise
- absolute overhead in microseconds is the primary metric
- p50 and mean are the clearest indicators of steady-state inline cost

For a full run-specific write-up, see [`bench/BENCHMARK_SUMMARY.md`](../../bench/BENCHMARK_SUMMARY.md).

## Short developer-facing copies

### X / Twitter

OxDeAI benchmarks: the protected execution path adds about `16-25 us p50` on a single worker on the tested machine.

That path includes deterministic policy evaluation plus authorization/envelope checks before a tool call. The result is a fail-closed authorization boundary for agent actions with bounded inline cost.

Reproducible locally:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both
```

Repo: `github.com/AngeYobo/oxdeai-core`

### Hacker News

OxDeAI is an authorization boundary for agent runtimes.

The model is simple: the runtime proposes an action, OxDeAI evaluates policy deterministically, emits an authorization on `ALLOW`, and the relying party verifies that authorization before any side effect executes. The goal is fail-closed execution control for tool calls, payments, provisioning, and similar agent actions.

We added a reproducible benchmark suite to measure the practical cost of that boundary. On the tested machine, the protected path adds about `16-25 us p50` in single-worker mode versus a baseline path without OxDeAI checks. The benchmark also measures `evaluate`, `verifyEnvelope`, and baseline vs protected execution directly.

The result is not zero cost, but it is small enough to be practical for many agent runtimes where the real downstream cost is usually network I/O, model calls, or external tool latency.

Important details:

- measured under Node.js on Linux/WSL2
- 100k iterations, 10k warmup, 5 runs
- concurrency 1 and 4 workers
- results depend on hardware/runtime
- benchmark is meant to be rerun, not treated as a universal constant

The repo includes the benchmark harness and generated output so the numbers can be inspected or reproduced.

### Reddit

OxDeAI is a deterministic authorization layer for agent actions.

We benchmarked the protected execution path, which includes policy evaluation and verification before tool execution. On the tested machine, the added overhead was about `16-25 us p50` in single-worker mode.

What matters is not the isolated microbenchmark, but that a fail-closed authorization boundary can be placed in front of agent actions with bounded runtime cost. That is useful for:

- tool execution
- external API calls
- payments
- provisioning flows

The benchmark is reproducible from the repo and reports `evaluate`, `verifyEnvelope`, `baselinePath`, and `protectedPath` separately.

### Developer summary

For an agent runtime, the relevant question is usually not whether authorization is fast in the abstract. The relevant question is whether a pre-execution policy boundary can be enforced without materially changing end-to-end runtime behavior.

The current OxDeAI measurements suggest that, on the tested host, the answer is yes for many runtime designs. A protected path adds roughly `16-25 us p50` in single-worker execution. In practice, that is small relative to the latency of most external side effects that agents trigger: HTTP requests, database writes, tool execution, queue operations, or settlement calls.

That overhead buys a specific property: deterministic fail-closed execution control. The runtime can require a valid authorization artifact before the tool call happens, rather than relying on post-fact logging or heuristic filtering.

The benchmark is structured to make engineering review easier:

- `evaluate` isolates policy decision cost
- `verifyEnvelope` isolates verification artifact cost
- `baselinePath` gives a no-authorization comparison path
- `protectedPath` shows the actual inline cost of gating execution

These measurements are bounded inline overhead, not a promise that every environment will see the same number. Teams should rerun the benchmark on their own hardware and compare absolute microsecond overhead in a controlled way.

### Quickstart example

```bash
pnpm add @oxdeai/core
```

```ts
import { PolicyEngine } from "@oxdeai/core";

const engine = new PolicyEngine({
  policy_version: "1.0.0",
  engine_secret: "replace-with-a-real-secret",
  authorization_ttl_seconds: 60,
  authorization_issuer: "your-pdp",
  authorization_audience: "your-relying-party",
  policyId: "a".repeat(64),
});

const intent = {
  intent_id: "intent-001",
  agent_id: "agent-1",
  action_type: "PAYMENT",
  type: "EXECUTE",
  nonce: 1n,
  amount: 1000n,
  target: "merchant-1",
  timestamp: Math.floor(Date.now() / 1000),
  metadata_hash: "b".repeat(64),
  signature: "app-signature",
  depth: 0,
  tool_call: true,
};

const state = {
  policy_version: "1.0.0",
  period_id: "period-2026-03",
  kill_switch: { global: false, agents: {} },
  allowlists: {
    action_types: ["PAYMENT"],
    assets: [],
    targets: ["merchant-1"],
  },
  budget: {
    budget_limit: { "agent-1": 10_000n },
    spent_in_period: { "agent-1": 0n },
  },
  max_amount_per_action: { "agent-1": 2_000n },
  velocity: {
    config: { window_seconds: 60, max_actions: 100 },
    counters: {},
  },
  replay: {
    window_seconds: 3600,
    max_nonces_per_agent: 1024,
    nonces: {},
  },
  concurrency: {
    max_concurrent: { "agent-1": 10 },
    active: {},
    active_auths: {},
  },
  recursion: {
    max_depth: { "agent-1": 4 },
  },
  tool_limits: {
    window_seconds: 60,
    max_calls: { "agent-1": 100 },
    max_calls_by_tool: {},
    calls: {},
  },
};

const result = engine.evaluatePure(intent, state);

if (result.decision === "ALLOW") {
  console.log("authorized");
  console.log(result.authorization);
} else {
  console.log("denied");
  console.log(result.reasons);
}
```
