export type BenchmarkConfig = {
  scenario: "evaluate" | "verifyAuthorization" | "verifyEnvelope" | "all";
  workers: number;
  durationSeconds: number;
  warmupIterations: number;
  measureIterations: number;
  outputDir: string;
  strictVerifyEnvelope: boolean;
};

export const defaultBenchmarkConfig: BenchmarkConfig = {
  scenario: "all",
  workers: 4,
  durationSeconds: 30,
  warmupIterations: 20_000,
  measureIterations: 100_000,
  outputDir: "bench/outputs",
  strictVerifyEnvelope: false
};
