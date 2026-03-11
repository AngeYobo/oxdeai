# OxDeAI Benchmark Summary

## 1. Executive Summary

This benchmark evaluates the latency of the main OxDeAI authorization-path primitives on a single host under Node.js. The most meaningful scenarios are:

- `evaluate`: policy evaluation only
- `verifyEnvelope`: verification of the execution envelope
- `baselinePath`: synthetic execution path with no OxDeAI checks
- `protectedPath`: execution path with OxDeAI checks enabled

On the measured system, the protected execution path adds absolute overhead in the tens of microseconds at single-worker concurrency. For the single-worker run, `protectedPath` adds approximately:

- `+14.8 us` p50 and `+21.8 us` mean in `best-effort` mode
- `+16.6 us` p50 and `+25.2 us` mean in `strict` mode

The main conclusion is that OxDeAI authorization introduces tens-of-microseconds latency overhead while providing deterministic fail-closed execution control. These numbers are implementation- and environment-specific and should be compared only across similar hardware and runtime configurations.

## 2. Benchmark Methodology

The benchmark was executed from the OxDeAI benchmark harness with:

- 10,000 warmup iterations
- 100,000 measured iterations
- 5 runs per scenario
- concurrency levels of 1 and 4 workers
- envelope modes `best-effort` and `strict`

The scenarios are defined as follows:

- `evaluate`: runs policy evaluation against a representative in-memory state
- `verifyEnvelope`: verifies an encoded execution envelope containing a snapshot and audit events
- `baselinePath`: runs deterministic synthetic tool-execution work with no OxDeAI checks
- `protectedPath`: runs the protected execution flow, consisting of evaluation, authorization verification, envelope verification, and the same synthetic tool-execution work as the baseline

Reported values are medians across runs for p50, p95, p99, and mean latency. Absolute overhead is computed as:

`protectedPath - baselinePath`

This report focuses on absolute latency in microseconds because relative percentages can be misleading when the baseline is already very small.

## 3. Environment Description

Benchmark host:

- CPU: Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz
- Logical cores: 4
- OS: Linux 5.15.133.1-microsoft-standard-WSL2 x64
- Runtime: Node.js v22.9.0
- Architecture: x64
- Environment: WSL2

Benchmark configuration:

- Scenario set: `all`
- Seed: `20260310`
- Warmup iterations: `10000`
- Measured iterations: `100000`
- Runs: `5`
- Concurrency: `1, 4`
- Envelope modes: `best-effort`, `strict`

Because the benchmark was run under WSL2 and JavaScript runtime scheduling, the results should be treated as host-specific measurements rather than protocol-intrinsic constants.

## 4. Latency Analysis

### Single-worker latency

| Scenario | p50 (us) | p95 (us) | p99 (us) | mean (us) | Status |
|---|---:|---:|---:|---:|---|
| `evaluate` | 23.833 | 37.501 | 64.520 | 29.956 | NOISY |
| `verifyEnvelope` (`best-effort`) | 15.457 | 21.654 | 45.956 | 17.199 | NOISY |
| `verifyEnvelope` (`strict`) | 15.546 | 22.307 | 46.339 | 17.140 | NOISY |
| `baselinePath` | 8.495 | 8.891 | 23.077 | 8.993 | OK |
| `protectedPath` (`best-effort`) | 23.326 | 37.275 | 69.070 | 30.843 | NOISY |
| `protectedPath` (`strict`) | 25.075 | 40.306 | 77.067 | 34.208 | NOISY |

Observations:

- `baselinePath` is the most stable single-worker measurement in this run.
- `verifyEnvelope` is consistently in the mid-teens of microseconds.
- `evaluate` is higher than `verifyEnvelope`, which is expected because it executes policy logic over a representative state.
- `protectedPath` remains in the low tens of microseconds at p50 under single-worker execution.

### Four-worker latency

| Scenario | p50 (us) | p95 (us) | p99 (us) | mean (us) | Status |
|---|---:|---:|---:|---:|---|
| `evaluate` | 85.368 | 129.977 | 438.090 | 119.465 | NOISY |
| `verifyEnvelope` (`best-effort`) | 16.844 | 22.522 | 44.548 | 19.420 | NOISY |
| `verifyEnvelope` (`strict`) | 16.896 | 22.385 | 44.937 | 20.351 | NOISY |
| `baselinePath` | 7.682 | 9.079 | 18.554 | 8.548 | NOISY |
| `protectedPath` (`best-effort`) | 128.727 | 187.245 | 694.495 | 167.152 | NOISY |
| `protectedPath` (`strict`) | 129.165 | 189.897 | 767.256 | 168.076 | NOISY |

Observations:

- Multi-worker results are materially noisier.
- `verifyEnvelope` remains relatively stable under 4 workers.
- `evaluate` and `protectedPath` widen substantially in p95/p99 under concurrent execution, which suggests runtime scheduling and shared-resource effects dominate more of the tail.
- For engineering interpretation, the single-worker p50 and mean are the clearest indicators of per-operation cost.

## 5. Baseline vs Protected Execution Overhead

Absolute overhead is the most useful measure for this benchmark.

### Single-worker overhead

| Protected mode | Delta p50 (us) | Delta p95 (us) | Delta p99 (us) | Delta mean (us) |
|---|---:|---:|---:|---:|
| `best-effort` | 14.831 | 28.384 | 45.993 | 21.850 |
| `strict` | 16.580 | 31.415 | 53.990 | 25.215 |

### Four-worker overhead

| Protected mode | Delta p50 (us) | Delta p95 (us) | Delta p99 (us) | Delta mean (us) |
|---|---:|---:|---:|---:|
| `best-effort` | 121.045 | 178.166 | 675.941 | 158.605 |
| `strict` | 121.483 | 180.818 | 748.702 | 159.528 |

Interpretation:

- At single-worker concurrency, the incremental cost of OxDeAI protection is on the order of `15-25 us` for p50/mean, depending on envelope mode.
- The difference between `best-effort` and `strict` envelope verification is small in absolute terms in this run, approximately `1.7-3.4 us`.
- Under 4-worker concurrency, the absolute overhead increases into the low hundreds of microseconds, indicating that scheduler effects and contention contribute more strongly than the underlying primitive costs.

## 6. Interpretation of Results

The benchmark supports a practical conclusion:

OxDeAI adds a small absolute latency cost to the protected execution path, measured in tens of microseconds for single-worker execution on this host.

That result is consistent with the structure of the protected path:

- policy evaluation
- authorization verification
- envelope verification
- execution gating before tool work

From a systems perspective, this is a bounded pre-execution cost rather than a dominant runtime component. For external operations such as network calls, provisioning actions, payments, or tool invocations, tens of microseconds are typically much smaller than the latency of the protected side effect itself.

The benchmark also shows that tail latency is more sensitive to concurrency than median latency. This suggests the protocol path is cheap enough that runtime and host scheduling effects become a substantial part of the observed distribution, especially at 4-worker concurrency.

## 7. Limitations and Reproducibility Notes

Several limitations are important when interpreting these numbers:

- Results depend on CPU model, clock behavior, memory hierarchy, kernel scheduling, and Node.js version.
- The benchmark was run under WSL2, which may differ from bare-metal Linux or containerized production deployment.
- Tail metrics at low absolute latencies are sensitive to runtime noise, garbage collection, and timer resolution.
- The benchmark uses deterministic synthetic tool work for `baselinePath` and `protectedPath`; this isolates authorization overhead, but it is not a substitute for end-to-end application latency measurement.
- The reported values describe this implementation and this environment, not a universal property of the protocol.

For reproducibility:

```bash
pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4 --envelopeMode=both
```

When comparing results across machines, prioritize:

- absolute overhead in microseconds
- p50 and mean for steady-state cost
- p95/p99 only across similar hardware/runtime environments

`verifyAuthorization` is intentionally not emphasized in this report because its standalone latency is close to the noise floor relative to the higher-signal end-to-end path measurements.
