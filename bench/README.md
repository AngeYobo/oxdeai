# OxDeAI Benchmark Suite

## Executive Summary

Latest full-suite local benchmark run:

- source: `bench/outputs/run-2026-03-11-12-25-55.json`
- machine: Intel Core i5-7400, 4 logical cores, Node.js v22.9.0, Linux on WSL2
- config: `--scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both`

Key results from that run indicate:

- `evaluate` p50 was `23.8 us` on 1 worker.
- `verifyEnvelope` p50 was `15.5 us` on 1 worker in both `best-effort` and `strict` modes.
- `baselinePath` and `protectedPath` provide the most useful adoption comparison.
- the key metric is absolute overhead (`protectedPath - baselinePath`) in microseconds.
- `protectedPath - baselinePath` was `+14.8 us p50` / `+21.8 us mean` in `best-effort` mode on 1 worker.
- `protectedPath - baselinePath` was `+16.6 us p50` / `+25.2 us mean` in `strict` mode on 1 worker.

Protected execution therefore adds on the order of tens of microseconds at `p50` in single-worker mode on the tested machine.

Results depend on hardware, runtime, and execution environment; the suite is designed to be reproducible rather than universal.

A fuller run-specific summary is available in [`BENCHMARK_SUMMARY.md`](./BENCHMARK_SUMMARY.md).

## Overview

The OxDeAI benchmark suite measures the performance characteristics of the OxDeAI authorization primitives.

The benchmark evaluates the latency and throughput of the deterministic authorization boundary used in agent execution environments.

Measured primitives:

- `evaluate()`
- `verifyAuthorization()`
- `verifyEnvelope()`

Primary benchmark scenarios:

- `evaluate`
- `verifyEnvelope`
- `baselinePath`
- `protectedPath`

Execution path scenarios:

- `baselinePath`
- `protectedPath`

The protected path represents a realistic execution flow including OxDeAI authorization checks.

## Benchmark Goals

The benchmark suite is designed to answer:

1. How expensive is OxDeAI policy evaluation?
2. How expensive is authorization verification?
3. How expensive is envelope verification?
4. What is the incremental cost of OxDeAI authorization in a realistic execution path?

The most important measurement is:

`protectedPath - baselinePath`

which represents the incremental authorization overhead.

`verifyAuthorization` remains part of the suite for completeness, but it is not emphasized as a primary result because its latency is extremely small and often dominated by runtime noise.

## Why This Matters

Agent runtimes already spend time on orchestration, serialization, and tool execution overhead. OxDeAI should be evaluated as incremental boundary cost, not as isolated micro-function speed.

This suite measures the additional latency introduced by running the protected execution path versus a baseline runtime path.

OxDeAI is designed to add a small, bounded pre-execution authorization cost in exchange for deterministic fail-closed control.

## Benchmark Methodology

The benchmark follows common systems benchmarking practices.

### Warmup phase

The runtime is warmed up before measurement to allow:

- JIT optimization
- memory allocation stabilization
- cache warming

### Measurement phase

Each scenario runs for a fixed number of iterations.

Timing is captured using:

`process.hrtime.bigint()`

which provides nanosecond resolution.

Samples are stored in nanoseconds and reported in milliseconds.

For documentation and interpretation, the project also reports the main results in microseconds because the protected-path overhead is small enough that microsecond-scale absolute deltas are the most useful engineering view.

### Multiple runs

Each scenario can be executed multiple times (`--runs=N`) to reduce variance.

### Statistical metrics

Results include:

- p50 latency
- p95 latency
- p99 latency
- mean latency
- standard deviation
- coefficient of variation
- throughput (operations/sec)

Runs may be marked:

- `OK`
- `NOISY`
- `EXTREMELY_NOISY`

depending on the coefficient of variation.

## Benchmark Scenarios

### evaluate

Measures pure policy evaluation latency.

### verifyAuthorization

Measures the cost of verifying a cryptographic authorization artifact.

The benchmark fixture uses the reference shared-secret trust profile emitted by the bench
`PolicyEngine`, so `verifyAuthorization()` is run with `requireSignatureVerification: true`
and the benchmark HMAC secret. This avoids measuring the non-cryptographic fast path where
only field/binding checks are evaluated.

### verifyEnvelope

Measures verification of execution envelopes.

Supported modes:

- `best-effort`
- `strict`

### baselinePath

Synthetic execution path representing agent runtime work without OxDeAI.

The path performs deterministic synthetic tool execution.

No authorization checks occur.

### protectedPath

Execution path including OxDeAI authorization.

`evaluate -> verifyAuthorization -> verifyEnvelope -> tool execution`

The same synthetic tool execution is performed as in `baselinePath`.

This allows a clean comparison.

## Running the Benchmark

Install dependencies:

```bash
pnpm install
```

Run full benchmark:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4
```

Baseline only:

```bash
pnpm -C bench run run -- --scenario=baselinePath
```

Protected path:

```bash
pnpm -C bench run run -- --scenario=protectedPath --envelopeMode=both
```

## CLI Parameters

Parameter | Meaning
---|---
scenario | which scenario to run
runs | number of repeated runs
iterations | iterations per run
warmup | warmup iterations
concurrency | number of workers
envelopeMode | strict / best-effort / both

## Benchmark Output

Generated report files:

```text
bench/outputs/latest.json
bench/outputs/run-<timestamp>.json
```

JSON output includes:

- machine metadata
- Node.js version
- CPU information
- benchmark configuration
- per-scenario latency percentiles
- throughput
- noise classification

## Interpreting Results

The most meaningful metric is the absolute latency overhead between:

`protectedPath - baselinePath`

Percentage overhead may be misleading when the baseline path is extremely small.

Therefore absolute microsecond overhead should be considered the primary metric.

For the latest full-suite run on the tested host, the single-worker protected-path overhead was approximately:

- `+14.8 us p50` and `+21.8 us mean` in `best-effort`
- `+16.6 us p50` and `+25.2 us mean` in `strict`

This is the main performance result to communicate externally.

## Result Interpretation

Primary interpretation should focus on:

- baseline execution latency
- protected execution latency
- absolute authorization overhead

The benchmark is designed to emphasize absolute latency overhead in microseconds, not percentage overhead.

When baseline latency is very small, percentage deltas can become unstable and visually misleading even when absolute overhead remains bounded.

## How To Compare Across Machines

For cross-machine comparisons:

- compare absolute overhead first (microseconds), not only `ops/sec`
- compare `p50` / `p95` / `p99`, not only mean latency
- expect more jitter on laptops, WSL, VMs, and shared hosts
- use repeated single-worker runs for cleaner local interpretation (for example `--stabilityMode --runs=5`)

## Limitations

Benchmark results depend on:

- CPU
- Node.js runtime
- operating system
- virtualization environments

Results produced under WSL or VM environments may exhibit higher noise.

For best reproducibility, run on bare metal with minimal background load.
