#!/usr/bin/env tsx
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ChartJSNodeCanvas } from "chartjs-node-canvas";
import type { ChartConfiguration } from "chart.js";

type ResultRow = {
  label: string;
  workers: number;
  aggregate: {
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    opsPerSec: number;
  };
};

type LatestReport = {
  results?: ResultRow[];
  runResults?: ResultRow[];
  aggregatedResults?: Record<string, ResultRow>;
};

const WIDTH = 1200;
const HEIGHT = 700;

function readLatest(repoRoot: string): LatestReport {
  const latestPath = path.join(repoRoot, "bench", "outputs", "latest.json");
  const raw = fs.readFileSync(latestPath, "utf8");
  return JSON.parse(raw) as LatestReport;
}

function rowsFromReport(report: LatestReport): ResultRow[] {
  if (report.runResults && report.runResults.length > 0) return report.runResults;
  if (report.results && report.results.length > 0) return report.results;
  if (report.aggregatedResults) return Object.values(report.aggregatedResults);
  return [];
}

function ensureGraphsDir(repoRoot: string): string {
  const graphsDir = path.join(repoRoot, "bench", "outputs", "graphs");
  fs.mkdirSync(graphsDir, { recursive: true });
  return graphsDir;
}

function buildLatencyConfig(
  title: string,
  rows: ResultRow[],
  metricAccessor: (r: ResultRow) => number
): ChartConfiguration<"bar"> {
  const sorted = [...rows].sort((a, b) => a.workers - b.workers);
  const labels = sorted.map((r) => `${r.workers} worker${r.workers > 1 ? "s" : ""}`);
  return {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "p50 (ms)",
          data: sorted.map((r) => r.aggregate.p50Ms),
          backgroundColor: "#4c78a8",
        },
        {
          label: "p95 (ms)",
          data: sorted.map((r) => r.aggregate.p95Ms),
          backgroundColor: "#f58518",
        },
        {
          label: "p99 (ms)",
          data: sorted.map((r) => r.aggregate.p99Ms),
          backgroundColor: "#e45756",
        },
        {
          label: "mean (ms)",
          data: sorted.map(metricAccessor),
          backgroundColor: "#72b7b2",
        },
      ],
    },
    options: {
      responsive: false,
      plugins: {
        title: { display: true, text: title },
        legend: { position: "top" },
      },
      scales: {
        x: { title: { display: true, text: "Concurrency" } },
        y: { title: { display: true, text: "Latency (ms)" }, beginAtZero: true },
      },
    },
  };
}

function buildBaselineVsProtectedConfig(rows: ResultRow[]): ChartConfiguration<"bar"> {
  const byWorkers = new Map<number, ResultRow[]>();
  for (const row of rows) {
    if (
      row.label === "baselinePath" ||
      row.label === "protectedPath(best-effort)" ||
      row.label === "protectedPath(strict)"
    ) {
      const list = byWorkers.get(row.workers) ?? [];
      list.push(row);
      byWorkers.set(row.workers, list);
    }
  }
  const workerKeys = [...byWorkers.keys()].sort((a, b) => a - b);
  const labels = workerKeys.map((w) => `${w} worker${w > 1 ? "s" : ""}`);

  const pick = (worker: number, label: string) =>
    byWorkers.get(worker)?.find((r) => r.label === label)?.aggregate;

  const toUs = (ms: number) => ms * 1000;

  return {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "baselinePath p50 (µs)",
          data: workerKeys.map((w) => toUs(pick(w, "baselinePath")?.p50Ms ?? 0)),
          backgroundColor: "#4c78a8",
        },
        {
          label: "protectedPath(best-effort) p50 (µs)",
          data: workerKeys.map((w) => toUs(pick(w, "protectedPath(best-effort)")?.p50Ms ?? 0)),
          backgroundColor: "#f58518",
        },
        {
          label: "absolute overhead p50 (µs)",
          data: workerKeys.map((w) =>
            toUs(
              (pick(w, "protectedPath(best-effort)")?.p50Ms ?? 0) -
                (pick(w, "baselinePath")?.p50Ms ?? 0)
            )
          ),
          backgroundColor: "#e45756",
        },
        {
          label: "absolute overhead p95 (µs)",
          data: workerKeys.map((w) =>
            toUs(
              (pick(w, "protectedPath(best-effort)")?.p95Ms ?? 0) -
                (pick(w, "baselinePath")?.p95Ms ?? 0)
            )
          ),
          backgroundColor: "#72b7b2",
        },
        {
          label: "absolute overhead p99 (µs)",
          data: workerKeys.map((w) =>
            toUs(
              (pick(w, "protectedPath(best-effort)")?.p99Ms ?? 0) -
                (pick(w, "baselinePath")?.p99Ms ?? 0)
            )
          ),
          backgroundColor: "#e45756",
        },
      ],
    },
    options: {
      responsive: false,
      plugins: {
        title: { display: true, text: "Baseline vs Protected Path and Absolute Overhead" },
        legend: { position: "top" },
      },
      scales: {
        x: { title: { display: true, text: "Concurrency" } },
        y: { title: { display: true, text: "Latency / Overhead (µs)" }, beginAtZero: true },
      },
    },
  };
}

function buildThroughputConfig(rows: ResultRow[]): ChartConfiguration<"bar"> {
  const sorted = [...rows].sort((a, b) => a.workers - b.workers || a.label.localeCompare(b.label));
  return {
    type: "bar",
    data: {
      labels: sorted.map((r) => `${r.label} (${r.workers}w)`),
      datasets: [
        {
          label: "Throughput (ops/sec)",
          data: sorted.map((r) => r.aggregate.opsPerSec),
          backgroundColor: "#54a24b",
        },
      ],
    },
    options: {
      responsive: false,
      plugins: {
        title: { display: true, text: "Scenario Throughput" },
        legend: { position: "top" },
      },
      scales: {
        x: { title: { display: true, text: "Scenario (workers)" } },
        y: { title: { display: true, text: "Operations / second" }, beginAtZero: true },
      },
    },
  };
}

function buildTailLatencyConfig(rows: ResultRow[]): ChartConfiguration<"line"> {
  const selectedLabels = ["evaluate", "verifyEnvelope(best-effort)", "baselinePath", "protectedPath(best-effort)"];
  const workers = Array.from(new Set(rows.map((r) => r.workers))).sort((a, b) => a - b);
  const toSeries = (label: string) =>
    workers.map((w) => rows.find((r) => r.label === label && r.workers === w)?.aggregate.p99Ms ?? null);

  return {
    type: "line",
    data: {
      labels: workers.map((w) => `${w}`),
      datasets: [
        { label: "evaluate p99 (ms)", data: toSeries(selectedLabels[0]), borderColor: "#4c78a8", backgroundColor: "#4c78a8" },
        {
          label: "verifyEnvelope(best-effort) p99 (ms)",
          data: toSeries(selectedLabels[1]),
          borderColor: "#f58518",
          backgroundColor: "#f58518",
        },
        { label: "baselinePath p99 (ms)", data: toSeries(selectedLabels[2]), borderColor: "#54a24b", backgroundColor: "#54a24b" },
        {
          label: "protectedPath(best-effort) p99 (ms)",
          data: toSeries(selectedLabels[3]),
          borderColor: "#e45756",
          backgroundColor: "#e45756",
        },
      ],
    },
    options: {
      responsive: false,
      plugins: {
        title: { display: true, text: "Tail Latency vs Workers (p99)" },
        legend: { position: "top" },
      },
      scales: {
        x: { title: { display: true, text: "Workers" } },
        y: { title: { display: true, text: "p99 Latency (ms)" }, beginAtZero: true },
      },
    },
  };
}

async function saveChart(filePath: string, config: ChartConfiguration): Promise<void> {
  const canvas = new ChartJSNodeCanvas({ width: WIDTH, height: HEIGHT, backgroundColour: "white" });
  const image = await canvas.renderToBuffer(config as any, "image/png");
  fs.writeFileSync(filePath, image);
}

async function main(): Promise<void> {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const report = readLatest(repoRoot);
  const graphsDir = ensureGraphsDir(repoRoot);
  const rows = rowsFromReport(report);

  const evaluateRows = rows.filter((r) => r.label === "evaluate");
  const verifyEnvelopeRows = rows.filter((r) => r.label.startsWith("verifyEnvelope"));
  const staleAuthorizationGraph = path.join(graphsDir, "authorization-latency.png");
  if (fs.existsSync(staleAuthorizationGraph)) fs.rmSync(staleAuthorizationGraph);

  await saveChart(
    path.join(graphsDir, "evaluate-latency.png"),
    buildLatencyConfig("evaluate() Latency", evaluateRows, (r) => r.aggregate.p50Ms)
  );
  await saveChart(
    path.join(graphsDir, "verifyEnvelope-latency.png"),
    buildLatencyConfig("verifyEnvelope() Latency", verifyEnvelopeRows, (r) => r.aggregate.p50Ms)
  );
  await saveChart(
    path.join(graphsDir, "baseline-vs-protected.png"),
    buildBaselineVsProtectedConfig(rows)
  );
  await saveChart(path.join(graphsDir, "throughput.png"), buildThroughputConfig(rows));
  await saveChart(path.join(graphsDir, "tail-latency-vs-workers.png"), buildTailLatencyConfig(rows));

  console.log("Generated graphs:");
  console.log(`- ${path.join(graphsDir, "evaluate-latency.png")}`);
  console.log(`- ${path.join(graphsDir, "verifyEnvelope-latency.png")}`);
  console.log(`- ${path.join(graphsDir, "baseline-vs-protected.png")}`);
  console.log(`- ${path.join(graphsDir, "throughput.png")}`);
  console.log(`- ${path.join(graphsDir, "tail-latency-vs-workers.png")}`);
}

main().catch((error) => {
  console.error("Failed to generate graphs");
  console.error(error);
  process.exit(1);
});
