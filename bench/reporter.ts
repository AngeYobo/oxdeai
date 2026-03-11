import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ScenarioRun } from "./runner-core.js";
import { nsToMs } from "./metrics.js";

export function collectEnvironment() {
  const cpus = os.cpus();
  const release = os.release().toLowerCase();
  return {
    cpuModel: cpus[0]?.model ?? "unknown",
    cpuCores: cpus.length,
    nodeVersion: process.version,
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    architecture: os.arch(),
    timestamp: new Date().toISOString(),
    isWSL: release.includes("microsoft"),
  };
}

function fmtMs(ns: number): string {
  return `${nsToMs(ns).toFixed(4)}ms`;
}

export function printReportHeader(): void {
  console.log("scenario                     workers runs iter       p50       p95       p99       mean      ops/sec   cv        status            notes");
  console.log("---------------------------  ------- ---- ---------- --------- --------- --------- --------- --------- --------- ----------------  ----------------");
}

export function reportRun(run: ScenarioRun): void {
  const row = [
    run.label.padEnd(27),
    String(run.workers).padStart(7),
    String(run.runs).padStart(4),
    String(run.iterations).padStart(10),
    fmtMs(run.stats.p50).padStart(9),
    fmtMs(run.stats.p95).padStart(9),
    fmtMs(run.stats.p99).padStart(9),
    fmtMs(run.stats.mean).padStart(9),
    run.stats.opsPerSec.toFixed(0).padStart(9),
    `${(run.stats.cv * 100).toFixed(2)}%`.padStart(9),
    run.status.padStart(16),
    (run.outlierDetected ? "OUTLIER_DETECTED" : "").padStart(18),
  ].join(" ");
  console.log(row);
}

export function reportDelta(label: string, base: ScenarioRun, protectedRun: ScenarioRun): void {
  const nearZeroBaseline = nsToMs(base.stats.mean) < 0.005 || nsToMs(base.stats.p50) < 0.005;
  const abs = {
    p50: nsToMs(protectedRun.stats.p50 - base.stats.p50),
    p95: nsToMs(protectedRun.stats.p95 - base.stats.p95),
    p99: nsToMs(protectedRun.stats.p99 - base.stats.p99),
    mean: nsToMs(protectedRun.stats.mean - base.stats.mean),
  };
  console.log(`\nΔ overhead (${label}, workers=${base.workers})`);
  if (nearZeroBaseline) {
    console.log(
      `  p50 ${abs.p50.toFixed(4)}ms,` +
        ` p95 ${abs.p95.toFixed(4)}ms,` +
        ` p99 ${abs.p99.toFixed(4)}ms,` +
        ` mean ${abs.mean.toFixed(4)}ms`
    );
    console.log("  relative % omitted (near-zero baseline mean/p50 < 0.005ms)");
    return;
  }
  const rel = {
    p50: base.stats.p50 > 0 ? ((protectedRun.stats.p50 - base.stats.p50) / base.stats.p50) * 100 : 0,
    p95: base.stats.p95 > 0 ? ((protectedRun.stats.p95 - base.stats.p95) / base.stats.p95) * 100 : 0,
    p99: base.stats.p99 > 0 ? ((protectedRun.stats.p99 - base.stats.p99) / base.stats.p99) * 100 : 0,
    mean: base.stats.mean > 0 ? ((protectedRun.stats.mean - base.stats.mean) / base.stats.mean) * 100 : 0,
  };
  console.log(
    `  p50 ${abs.p50.toFixed(4)}ms (${rel.p50.toFixed(2)}%),` +
      ` p95 ${abs.p95.toFixed(4)}ms (${rel.p95.toFixed(2)}%),` +
      ` p99 ${abs.p99.toFixed(4)}ms (${rel.p99.toFixed(2)}%),` +
      ` mean ${abs.mean.toFixed(4)}ms (${rel.mean.toFixed(2)}%)`
  );
}

export function writeJsonOutputs(outputDir: string, payload: unknown): { latestPath: string; timestampedPath: string } {
  fs.mkdirSync(outputDir, { recursive: true });
  const latestPath = path.join(outputDir, "latest.json");
  const d = new Date();
  const stamp = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}-${String(d.getUTCHours()).padStart(2, "0")}-${String(d.getUTCMinutes()).padStart(2, "0")}-${String(d.getUTCSeconds()).padStart(2, "0")}`;
  const timestampedPath = path.join(outputDir, `run-${stamp}.json`);
  const body = JSON.stringify(payload, null, 2);
  fs.writeFileSync(latestPath, body, "utf8");
  fs.writeFileSync(timestampedPath, body, "utf8");
  return { latestPath, timestampedPath };
}

export function writeMarkdownSummary(
  outputDir: string,
  opts: {
    machine: ReturnType<typeof collectEnvironment>;
    config: Record<string, unknown>;
    runs: ScenarioRun[];
    deltas: Array<{
      workers: number;
      baselineLabel: string;
      protectedLabel: string;
      absoluteMs: { p50: number; p95: number; p99: number; mean: number };
    }>;
  }
): string {
  fs.mkdirSync(outputDir, { recursive: true });
  const summaryPath = path.join(outputDir, "summary.md");
  const selected = opts.runs.filter(
    (r) =>
      r.label === "evaluate" ||
      r.label.startsWith("verifyEnvelope") ||
      r.label === "baselinePath" ||
      r.label.startsWith("protectedPath")
  );
  const lines: string[] = [];
  lines.push("# OxDeAI Benchmark Summary");
  lines.push("");
  lines.push("## Machine");
  lines.push("");
  lines.push(`- CPU: ${opts.machine.cpuModel}`);
  lines.push(`- Logical cores: ${opts.machine.cpuCores}`);
  lines.push(`- Node: ${opts.machine.nodeVersion}`);
  lines.push(`- OS: ${opts.machine.os}`);
  lines.push(`- Architecture: ${opts.machine.architecture}`);
  lines.push(`- WSL: ${opts.machine.isWSL ? "yes" : "no"}`);
  lines.push(`- Timestamp: ${opts.machine.timestamp}`);
  lines.push("");
  lines.push("## Config");
  lines.push("");
  lines.push("```json");
  lines.push(JSON.stringify(opts.config, null, 2));
  lines.push("```");
  lines.push("");
  lines.push("## Key Scenarios");
  lines.push("");
  lines.push("| Scenario | Workers | p50 (µs) | p95 (µs) | p99 (µs) | mean (µs) | ops/sec | status |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|---|");
  for (const run of selected) {
    lines.push(
      `| ${run.label} | ${run.workers} | ${(nsToMs(run.stats.p50) * 1000).toFixed(2)} | ${(nsToMs(run.stats.p95) * 1000).toFixed(2)} | ${(nsToMs(run.stats.p99) * 1000).toFixed(2)} | ${(nsToMs(run.stats.mean) * 1000).toFixed(2)} | ${run.stats.opsPerSec.toFixed(0)} | ${run.status}${run.outlierDetected ? " + OUTLIER_DETECTED" : ""} |`
    );
  }
  lines.push("");
  lines.push("## Absolute Overhead (protectedPath - baselinePath)");
  lines.push("");
  lines.push("| Workers | Path | Δp50 (µs) | Δp95 (µs) | Δp99 (µs) | Δmean (µs) |");
  lines.push("|---:|---|---:|---:|---:|---:|");
  for (const d of opts.deltas) {
    lines.push(
      `| ${d.workers} | ${d.protectedLabel} vs ${d.baselineLabel} | ${(d.absoluteMs.p50 * 1000).toFixed(2)} | ${(d.absoluteMs.p95 * 1000).toFixed(2)} | ${(d.absoluteMs.p99 * 1000).toFixed(2)} | ${(d.absoluteMs.mean * 1000).toFixed(2)} |`
    );
  }
  lines.push("");
  lines.push("## Interpretation");
  lines.push("");
  lines.push("- Focus on absolute overhead (microseconds), not only percentage overhead.");
  lines.push("- `verifyAuthorization` is measured but treated as secondary due to noise-floor effects.");
  lines.push("- Results depend on hardware/runtime; compare p50/p95/p99 across similar environments.");

  fs.writeFileSync(summaryPath, `${lines.join("\n")}\n`, "utf8");
  return summaryPath;
}
