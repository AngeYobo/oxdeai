import { createFixtureSet, makeDeterministicToolExecutor } from "../fixtures";

export const name = "baselinePath";

export function create(seed: number): () => unknown {
  const fx = createFixtureSet(seed).complex;
  const executeTool = makeDeterministicToolExecutor();
  const actionType = fx.intent.action_type;
  const target = fx.intent.target;
  const amount = Number(fx.intent.amount);

  return () => {
    // Same shaped call site as protected path, without OxDeAI checks.
    return executeTool(actionType, target, amount);
  };
}
