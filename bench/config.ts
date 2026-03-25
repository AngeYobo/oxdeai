export type ScenarioName =
  | "evaluate"
  | "verifyAuthorization"
  | "verifyEnvelope"
  | "baselinePath"
  | "protectedPath"
  | "verifyDelegation";

export type BenchmarkConfig = {
  scenario: ScenarioName | "all";
  seed: number;
  warmupIterations: number;
  iterations: number;
  concurrency: number[];
  envelopeMode: "best-effort" | "strict" | "both";
  runs: number;
  outputDir: string;
  stabilityMode: boolean;
  help: boolean;
};

export const defaultBenchmarkConfig: BenchmarkConfig = {
  scenario: "all",
  seed: 20260310,
  warmupIterations: 10_000,
  iterations: 100_000,
  concurrency: [1, 4, 8, 16],
  envelopeMode: "both",
  runs: 1,
  outputDir: "bench/outputs",
  stabilityMode: false,
  help: false,
};

function parseConcurrency(raw: string): number[] {
  const parsed = raw
    .split(",")
    .map((v) => Number(v.trim()))
    .filter((v) => Number.isFinite(v) && v > 0)
    .map((v) => Math.floor(v));
  if (parsed.length === 0) return [...defaultBenchmarkConfig.concurrency];
  return Array.from(new Set(parsed)).sort((a, b) => a - b);
}

export function parseBenchmarkConfig(argv: readonly string[]): BenchmarkConfig {
  const config: BenchmarkConfig = {
    ...defaultBenchmarkConfig,
  };

  for (const raw of argv) {
    if (raw === "--help" || raw === "-h") {
      config.help = true;
      continue;
    }
    if (!raw.startsWith("--")) continue;
    const [k, v = ""] = raw.slice(2).split("=", 2);
    switch (k) {
      case "scenario":
        if (
          v === "all" ||
          v === "evaluate" ||
          v === "verifyAuthorization" ||
          v === "verifyEnvelope" ||
          v === "baselinePath" ||
          v === "protectedPath" ||
          v === "verifyDelegation"
        ) {
          config.scenario = v;
        }
        break;
      case "seed":
        config.seed = Number(v) || config.seed;
        break;
      case "warmup":
        config.warmupIterations = Math.max(10_000, Number(v) || config.warmupIterations);
        break;
      case "iterations":
        config.iterations = Math.max(100_000, Number(v) || config.iterations);
        break;
      case "concurrency":
        config.concurrency = parseConcurrency(v);
        break;
      case "strict":
        if (v === "true" || v === "") config.envelopeMode = "strict";
        else if (v === "false") config.envelopeMode = "best-effort";
        break;
      case "envelopemode":
      case "envelopeMode":
        if (v === "strict" || v === "best-effort" || v === "both") config.envelopeMode = v;
        break;
      case "output-dir":
        if (v) config.outputDir = v;
        break;
      case "runs":
        config.runs = Math.max(1, Math.floor(Number(v) || config.runs));
        break;
      case "stabilityMode":
      case "stabilitymode":
        config.stabilityMode = v === "" || v === "true" || v === "1";
        break;
      default:
        break;
    }
  }

  if (config.stabilityMode) {
    config.concurrency = [1];
    config.iterations = Math.max(500_000, config.iterations);
    config.warmupIterations = Math.max(50_000, config.warmupIterations);
  }

  if (!config.concurrency.includes(1)) config.concurrency = [1, ...config.concurrency];
  return config;
}

export function benchmarkHelpText(): string {
  return [
    "OxDeAI benchmark runner",
    "",
    "Usage:",
    "  pnpm -C bench run run -- --scenario=all --runs=5 --iterations=100000 --warmup=10000 --concurrency=1,4",
    "",
    "Scenarios:",
    "  evaluate | verifyAuthorization | verifyEnvelope | baselinePath | protectedPath | verifyDelegation | all",
    "",
    "Parameters:",
    "  --scenario=<name>                 Scenario to run (default: all)",
    "  --runs=<n>                        Repeated runs per scenario/worker (default: 1)",
    "  --iterations=<n>                  Measured iterations per run (default: 100000)",
    "  --warmup=<n>                      Warmup iterations per run (default: 10000)",
    "  --concurrency=<csv>               Worker counts, e.g. 1,4,8,16",
    "  --envelopeMode=<strict|best-effort|both>",
    "  --seed=<n>                        Deterministic fixture seed",
    "  --output-dir=<path>               Output directory for JSON reports",
    "  --stabilityMode                   Publication-oriented mode (forces concurrency=1, higher warmup/iterations)",
    "  --help                            Show this message",
    "",
    "Examples:",
    "  pnpm -C bench run run -- --scenario=all --runs=5 --concurrency=1,4",
    "  pnpm -C bench run run -- --scenario=protectedPath --envelopeMode=both",
    "  pnpm -C bench run run -- --scenario=all --stabilityMode --runs=5",
  ].join("\n");
}
