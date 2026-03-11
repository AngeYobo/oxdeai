#!/usr/bin/env tsx
import path from "node:path";
import { fileURLToPath } from "node:url";
import { benchmarkHelpText, parseBenchmarkConfig, type ScenarioName } from "./config.js";
import type { ScenarioHandle } from "./runner-core.js";
import { runScenario } from "./runner-core.js";
import * as evaluateCase from "./cases/evaluate.js";
import * as verifyAuthorizationCase from "./cases/verifyAuthorization.js";
import * as verifyEnvelopeCase from "./cases/verifyEnvelope.js";
import * as baselinePathCase from "./cases/baselinePath.js";
import * as protectedPathCase from "./cases/protectedPath.js";
import { collectEnvironment, printReportHeader, reportDelta, reportRun, writeJsonOutputs, writeMarkdownSummary } from "./reporter.js";
import { nsToMs } from "./metrics.js";
import type { ScenarioRun } from "./runner-core.js";

function buildScenarios(config: ReturnType<typeof parseBenchmarkConfig>): ScenarioHandle[] {
  const selected: ScenarioName[] =
    config.scenario === "all"
      ? ["evaluate", "verifyAuthorization", "verifyEnvelope", "baselinePath", "protectedPath"]
      : [config.scenario];
  const out: ScenarioHandle[] = [];

  for (const name of selected) {
    if (name === "evaluate") {
      out.push({
        scenario: "evaluate",
        label: "evaluate",
        work: evaluateCase.create(config.seed),
      });
      continue;
    }
    if (name === "verifyAuthorization") {
      out.push({
        scenario: "verifyAuthorization",
        label: "verifyAuthorization",
        work: verifyAuthorizationCase.create(config.seed),
      });
      continue;
    }
    if (name === "baselinePath") {
      out.push({
        scenario: "baselinePath",
        label: "baselinePath",
        work: baselinePathCase.create(config.seed),
      });
      continue;
    }
    if (name === "protectedPath") {
      if (config.envelopeMode === "both" || config.envelopeMode === "best-effort") {
        out.push({
          scenario: "protectedPath",
          label: "protectedPath(best-effort)",
          mode: "best-effort",
          work: protectedPathCase.create(config.seed, "best-effort"),
        });
      }
      if (config.envelopeMode === "both" || config.envelopeMode === "strict") {
        out.push({
          scenario: "protectedPath",
          label: "protectedPath(strict)",
          mode: "strict",
          work: protectedPathCase.create(config.seed, "strict"),
        });
      }
      continue;
    }
    if (config.envelopeMode === "both" || config.envelopeMode === "best-effort") {
      out.push({
        scenario: "verifyEnvelope",
        label: "verifyEnvelope(best-effort)",
        mode: "best-effort",
        work: verifyEnvelopeCase.create(config.seed, "best-effort"),
      });
    }
    if (config.envelopeMode === "both" || config.envelopeMode === "strict") {
      out.push({
        scenario: "verifyEnvelope",
        label: "verifyEnvelope(strict)",
        mode: "strict",
        work: verifyEnvelopeCase.create(config.seed, "strict"),
      });
    }
  }
  return out;
}

function toJsonStats(nsStats: ScenarioRun["stats"]) {
  return {
    count: nsStats.count,
    minNs: nsStats.min,
    maxNs: nsStats.max,
    meanNs: nsStats.mean,
    stddevNs: nsStats.stddev,
    p50Ns: nsStats.p50,
    p95Ns: nsStats.p95,
    p99Ns: nsStats.p99,
    p999Ns: nsStats.p999,
    minMs: nsToMs(nsStats.min),
    maxMs: nsToMs(nsStats.max),
    meanMs: nsToMs(nsStats.mean),
    stddevMs: nsToMs(nsStats.stddev),
    p50Ms: nsToMs(nsStats.p50),
    p95Ms: nsToMs(nsStats.p95),
    p99Ms: nsToMs(nsStats.p99),
    p999Ms: nsToMs(nsStats.p999),
    opsPerSec: nsStats.opsPerSec,
    cv: nsStats.cv,
  };
}

function toJsonRun(run: ScenarioRun) {
  const key = `${run.label}#w${run.workers}`;
  return {
    key,
    scenario: run.scenario,
    label: run.label,
    workers: run.workers,
    iterations: run.iterations,
    warmupIterations: run.warmupIterations,
    runs: run.runs,
    status: run.status,
    outlierDetected: run.outlierDetected,
    annotations: run.annotations,
    aggregate: toJsonStats(run.stats),
    perRun: run.perRun.map((stats, index) => ({
      runIndex: index,
      outlierDetected: stats.p50 > 0 && stats.max > stats.p50 * 100,
      ...toJsonStats(stats),
    })),
  };
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const config = parseBenchmarkConfig(argv);
  if (config.help) {
    console.log(benchmarkHelpText());
    return 0;
  }
  const scenarios = buildScenarios(config);
  const allRuns: ScenarioRun[] = [];

  printReportHeader();
  for (const scenario of scenarios) {
    for (const workers of config.concurrency) {
      const run = await runScenario(scenario, config, workers);
      reportRun(run);
      allRuns.push(run);
    }
  }

  const deltas = [];
  const baselinesByWorker = new Map<number, ScenarioRun>();
  for (const run of allRuns) {
    if (run.scenario === "baselinePath") baselinesByWorker.set(run.workers, run);
  }
  for (const run of allRuns) {
    if (run.scenario !== "protectedPath") continue;
    const baseline = baselinesByWorker.get(run.workers);
    if (!baseline) continue;
    const nearZeroBaseline = nsToMs(baseline.stats.mean) < 0.005 || nsToMs(baseline.stats.p50) < 0.005;
    const delta = {
      workers: run.workers,
      baselineLabel: baseline.label,
      protectedLabel: run.label,
      absoluteMs: {
        p50: nsToMs(run.stats.p50 - baseline.stats.p50),
        p95: nsToMs(run.stats.p95 - baseline.stats.p95),
        p99: nsToMs(run.stats.p99 - baseline.stats.p99),
        mean: nsToMs(run.stats.mean - baseline.stats.mean),
      },
      relativePct: nearZeroBaseline
        ? null
        : {
            p50: baseline.stats.p50 > 0 ? ((run.stats.p50 - baseline.stats.p50) / baseline.stats.p50) * 100 : 0,
            p95: baseline.stats.p95 > 0 ? ((run.stats.p95 - baseline.stats.p95) / baseline.stats.p95) * 100 : 0,
            p99: baseline.stats.p99 > 0 ? ((run.stats.p99 - baseline.stats.p99) / baseline.stats.p99) * 100 : 0,
            mean: baseline.stats.mean > 0 ? ((run.stats.mean - baseline.stats.mean) / baseline.stats.mean) * 100 : 0,
          },
      relativeSuppressed: nearZeroBaseline,
      relativeSuppressedReason: nearZeroBaseline ? "baseline mean/p50 below 0.005ms" : undefined,
    };
    deltas.push(delta);
    reportDelta(run.label, baseline, run);
  }

  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const outputDir = path.isAbsolute(config.outputDir) ? config.outputDir : path.join(repoRoot, config.outputDir);
  const machine = collectEnvironment();
  const runResults = allRuns.map(toJsonRun);
  const aggregatedResults: Record<string, unknown> = {};
  for (const run of runResults) {
    aggregatedResults[run.key] = {
      scenario: run.scenario,
      label: run.label,
      workers: run.workers,
      iterations: run.iterations,
      warmupIterations: run.warmupIterations,
      runs: run.runs,
      status: run.status,
      outlierDetected: run.outlierDetected,
      annotations: run.annotations,
      aggregate: run.aggregate,
    };
  }
  const payload = {
    machine,
    timestamp: new Date().toISOString(),
    config,
    runResults,
    aggregatedResults,
    // Backward-compatible alias for existing tools.
    results: runResults,
    overheadDelta: deltas,
  };
  const files = writeJsonOutputs(outputDir, payload);
  const summaryPath = writeMarkdownSummary(outputDir, {
    machine,
    config: config as unknown as Record<string, unknown>,
    runs: allRuns,
    deltas: deltas as Array<{
      workers: number;
      baselineLabel: string;
      protectedLabel: string;
      absoluteMs: { p50: number; p95: number; p99: number; mean: number };
    }>,
  });
  console.log(`\nJSON written: ${files.latestPath}`);
  console.log(`JSON written: ${files.timestampedPath}`);
  console.log(`Markdown summary written: ${summaryPath}`);
  return 0;
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectRun) {
  main().then((code) => process.exit(code)).catch((error) => {
    console.error("Benchmark error:", error);
    process.exit(1);
  });
}
