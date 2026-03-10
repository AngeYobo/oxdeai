import { runScenario, type ScenarioHandle } from "./runner-core.js";
import { defaultBenchmarkConfig } from "./config.js";

function busyWork(): void {
  let x = 0;
  for (let i = 0; i < 1000; i++) {
    x += i;
  }

  if (x === Number.MIN_SAFE_INTEGER) {
    throw new Error("unreachable");
  }
}

async function main(): Promise<void> {
  console.log("[bench] starting");

  const scenario: ScenarioHandle = {
    name: "smoke-test",
    work: busyWork,
  };

  const result = await runScenario(scenario, defaultBenchmarkConfig);

  console.log(`[bench] scenario: ${result.scenario}`);
  console.log(result.stats);
  console.log("[bench] finished");
}

main().catch((err) => {
  console.error("[bench] failed");
  console.error(err);
  process.exit(1);
});