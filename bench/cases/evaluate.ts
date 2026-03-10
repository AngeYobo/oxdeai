import { makeEngine, makeIntent, makeState } from "../fixtures";

export const name = "evaluate";

export function create(): () => void {
  const engine = makeEngine();
  const intent = makeIntent();
  const state = makeState();

  return () => {
    engine.evaluate(intent, state);
  };
}
