export type LatencySample = number; // nanoseconds

export type LatencyStats = {
  count: number;
  min: number;
  max: number;
  mean: number;
  stddev: number;
  p50: number;
  p95: number;
  p99: number;
  throughput: number;
};

export function nsToUs(ns: number): number {
  return ns / 1000;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (hi === lo) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

export function computeLatencyStats(samples: LatencySample[], elapsedSeconds: number): LatencyStats {
  const sorted = [...samples].sort((a, b) => a - b);
  const count = sorted.length;
  const min = count > 0 ? sorted[0] : 0;
  const max = count > 0 ? sorted[count - 1] : 0;
  const mean = count > 0 ? sorted.reduce((sum, x) => sum + x, 0) / count : 0;
  const variance =
    count > 1 ? sorted.reduce((sum, x) => sum + (x - mean) ** 2, 0) / (count - 1) : 0;
  const stddev = Math.sqrt(variance);

  return {
    count,
    min,
    max,
    mean,
    stddev,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    throughput: elapsedSeconds > 0 ? count / elapsedSeconds : 0
  };
}
