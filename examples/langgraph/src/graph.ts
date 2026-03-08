/**
 * graph.ts — LangGraph workflow that proposes tool calls.
 *
 * This is the framework-specific part of the demo.
 * OxDeAI policy checks remain outside the graph at the PEP boundary.
 */

import { Annotation, END, START, StateGraph } from "@langchain/langgraph";

export type ProposedCall = {
  sequence: number;
  asset: string;
  region: string;
};

const GraphState = Annotation.Root({
  objective: Annotation<string>(),
  proposals: Annotation<ProposedCall[]>({
    reducer: (left, right) => left.concat(right),
    default: () => [],
  }),
});

async function proposeToolsNode(
  state: typeof GraphState.State
): Promise<Partial<typeof GraphState.State>> {
  void state.objective;
  return {
    proposals: [
      { sequence: 1, asset: "a100", region: "us-east-1" },
      { sequence: 2, asset: "a100", region: "us-east-1" },
      { sequence: 3, asset: "a100", region: "us-east-1" },
    ],
  };
}

const compiled = new StateGraph(GraphState)
  .addNode("propose_tools", proposeToolsNode)
  .addEdge(START, "propose_tools")
  .addEdge("propose_tools", END)
  .compile();

export async function proposeCallsViaLangGraph(
  log: (msg: string) => void
): Promise<readonly ProposedCall[]> {
  log("\n── LangGraph workflow ───────────────────────────────────────────────");
  log("   node: propose_tools");

  const out = await compiled.invoke({
    objective: "Provision three a100 instances in us-east-1",
    proposals: [],
  });

  const proposals = out.proposals ?? [];
  log(`   proposed tool calls: ${proposals.length}`);
  return proposals;
}
