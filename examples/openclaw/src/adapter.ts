// SPDX-License-Identifier: Apache-2.0
export type OpenClawProposal = {
  sequence: number;
  asset: string;
  region: string;
  workflow_id: string;
  step_id: string;
};

export async function proposeCallsViaOpenClaw(
  log: (msg: string) => void
): Promise<readonly OpenClawProposal[]> {
  log("\n── OpenClaw runtime flow ───────────────────────────────────────────");
  log("   workflow: planner -> action dispatcher");
  const proposals = [
    {
      sequence: 1,
      asset: "a100",
      region: "us-east-1",
      workflow_id: "openclaw-gpu-demo",
      step_id: "step-1"
    },
    {
      sequence: 2,
      asset: "a100",
      region: "us-east-1",
      workflow_id: "openclaw-gpu-demo",
      step_id: "step-2"
    },
    {
      sequence: 3,
      asset: "a100",
      region: "us-east-1",
      workflow_id: "openclaw-gpu-demo",
      step_id: "step-3"
    }
  ] as const;
  log(`   proposed tool calls: ${proposals.length}`);
  return proposals;
}
