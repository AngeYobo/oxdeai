#!/usr/bin/env ts-node
import { defaultBenchmarkConfig } from "./config";
import { runScenario, type ScenarioHandle } from "./runner-core";
import * as evaluateCase from "./cases/evaluate";
import * as verifyAuthorizationCase from "./cases/verifyAuthorization";
import * as verifyEnvelopeCase from "./cases/verifyEnvelope";
import { reportRun, reportJson } from "./reporter";

function parseArgs(): Partial<typeof defaultBenchmarkConfig> {
  const args = process.argv.slice(2);
  const result: any = {};

  for (const arg of args) {
    if (!arg.startsWith("--")) continue;
    const [k, v] = arg.slice(2).split("=");
    result[k] = v === undefined ? true : isNaN(Number(v)) ? v : Number(v);
  }

  return result;
}

async function main() {
  const flags = parseArgs();
  const config = { ...defaultBenchmarkConfig, ...(flags as any) };

  const scenarios: ScenarioHandle[] = [];
  if (config.scenario === "all" || config.scenario === "evaluate") {
    scenarios.push({ name: evaluateCase.name, work: evaluateCase.create() });
  }
  if (config.scenario === "all" || config.scenario === "verifyAuthorization") {
    scenarios.push({ name: verifyAuthorizationCase.name, work: verifyAuthorizationCase.create() });
  }
  if (config.scenario === "all" || config.scenario === "verifyEnvelope") {
    scenarios.push({ name: verifyEnvelopeCase.name, work: verifyEnvelopeCase.create(config.strictVerifyEnvelope) });
  }

  const fullReport: any = {
    run_at: new Date().toISOString(),
    config,
    results: [] as any[]
  };

  for (const scenario of scenarios) {
    const { stats } = await runScenario(scenario, config);
    reportRun(scenario.name, config, stats);
    fullReport.results.push({ scenario: scenario.name, stats });
  }

  const filePath = `${config.outputDir}/latest.json`;
  reportJson(filePath, fullReport);
  const timestamped = `${config.outputDir}/run-${new Date().toISOString().replace(/:/g, "-")}.json`;
  reportJson(timestamped, fullReport);
}

main().catch((error) => {
  console.error("Benchmark error:", error);
  process.exit(1);
});
