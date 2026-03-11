export type LatencyStats = {
  count: number;
  min: number;
  max: number;
  mean: number;
  stddev: number;
  p50: number;
  p95: number;
  p99: number;
  p999: number;
  opsPerSec: number;
  cv: number;
};

export function nsToMs(ns: number): number {
  return ns / 1_000_000;
}

function percentileFromSorted(sorted: Float64Array, p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  const w = idx - lo;
  return sorted[lo] * (1 - w) + sorted[hi] * w;
}

export function measureIterations(iterations: number, work: () => unknown): { samplesNs: Float64Array; elapsedNs: number; sink: number } {
  const samplesNs = new Float64Array(iterations);
  let sink = 0;
  const allStartNs = process.hrtime.bigint();

  for (let i = 0; i < iterations; i++) {
    const startNs = process.hrtime.bigint();
    const out = work();
    const endNs = process.hrtime.bigint();
    samplesNs[i] = Number(endNs - startNs);

    // Consume return values to prevent dead-code elimination.
    if (typeof out === "number") sink ^= out | 0;
    else if (typeof out === "string") sink ^= out.length;
    else if (out && typeof out === "object") sink ^= Object.keys(out as Record<string, unknown>).length;
  }

  const elapsedNs = Number(process.hrtime.bigint() - allStartNs);
  return { samplesNs, elapsedNs, sink };
}

export function computeLatencyStats(samplesNs: Float64Array, elapsedNs: number): LatencyStats {
  const count = samplesNs.length;
  if (count === 0) {
    return {
      count: 0,
      min: 0,
      max: 0,
      mean: 0,
      stddev: 0,
      p50: 0,
      p95: 0,
      p99: 0,
      p999: 0,
      opsPerSec: 0,
      cv: 0,
    };
  }

  let min = Number.POSITIVE_INFINITY;
  let max = 0;
  let sum = 0;
  for (let i = 0; i < count; i++) {
    const x = samplesNs[i];
    if (x < min) min = x;
    if (x > max) max = x;
    sum += x;
  }
  const mean = sum / count;
  let varianceAcc = 0;
  for (let i = 0; i < count; i++) {
    const d = samplesNs[i] - mean;
    varianceAcc += d * d;
  }
  const stddev = Math.sqrt(varianceAcc / Math.max(1, count - 1));
  const cv = mean > 0 ? stddev / mean : 0;

  const sorted = new Float64Array(samplesNs);
  sorted.sort();
  return {
    count,
    min,
    max,
    mean,
    stddev,
    p50: percentileFromSorted(sorted, 50),
    p95: percentileFromSorted(sorted, 95),
    p99: percentileFromSorted(sorted, 99),
    p999: percentileFromSorted(sorted, 99.9),
    opsPerSec: elapsedNs > 0 ? (count * 1_000_000_000) / elapsedNs : 0,
    cv,
  };
}

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}
