export type ProposedCall = {
  sequence: number;
  asset: string;
  region: string;
};

export async function proposeCallsViaOpenAIAgents(
  log: (msg: string) => void
): Promise<readonly ProposedCall[]> {
  log("\n── OpenAI Agents SDK workflow ──────────────────────────────────────");
  log("   agent: planning node -> tool proposals");
  const proposals = [
    { sequence: 1, asset: "a100", region: "us-east-1" },
    { sequence: 2, asset: "a100", region: "us-east-1" },
    { sequence: 3, asset: "a100", region: "us-east-1" },
  ] as const;
  log(`   proposed tool calls: ${proposals.length}`);
  return proposals;
}
