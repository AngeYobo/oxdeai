import type { LatencyStats } from "./metrics";

export function reportRun(scenario: string, config: { workers:number; durationSeconds:number }, stats: LatencyStats): void {
  const toUs = (n: number) => (n / 1000).toFixed(2);

  console.log("\n=== OxDeAI Benchmark Report ===");
  console.log(`scenario: ${scenario}`);
  console.log(`workers: ${config.workers}, duration: ${config.durationSeconds}s`);
  console.log(`ops/sec: ${stats.throughput.toFixed(1)}`);
  console.log(`latency p50: ${toUs(stats.p50)}us p95: ${toUs(stats.p95)}us p99: ${toUs(stats.p99)}us`);
  console.log(`mean: ${toUs(stats.mean)}us stddev: ${toUs(stats.stddev)}us`);
  console.log(`count: ${stats.count}, min: ${toUs(stats.min)}us, max: ${toUs(stats.max)}us`);
}

export function reportJson(path: string, payload: unknown): void {
  const fs = require("fs");
  fs.mkdirSync(path.replace(/\/[^/]*$/, ""), { recursive: true });
  fs.writeFileSync(path, JSON.stringify(payload, null, 2), "utf8");
}
