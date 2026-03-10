import { computeLatencyStats } from "./metrics";
import type { LatencyStats } from "./metrics";
import type { BenchmarkConfig } from "./config";

export type ScenarioHandle = {
  name: string;
  work: () => void;
};

export async function runScenario(
  scenario: ScenarioHandle,
  config: BenchmarkConfig
): Promise<{ stats: LatencyStats; scenario: string }> {
  const warmupIterations = config.warmupIterations;

  for (let i = 0; i < warmupIterations; i++) {
    scenario.work();
  }

  const samples: number[] = [];
  const maxSamples = config.measureIterations;
  const start = process.hrtime.bigint();
  const stop = start + BigInt(config.durationSeconds * 1e9);

  while (process.hrtime.bigint() < stop && samples.length < maxSamples) {
    const s = process.hrtime.bigint();
    scenario.work();
    const e = process.hrtime.bigint();
    samples.push(Number(e - s));
  }

  const end = process.hrtime.bigint();
  const elapsedSeconds = Number(end - start) / 1e9;
  const stats = computeLatencyStats(samples, elapsedSeconds);

  return { stats, scenario: scenario.name };
}