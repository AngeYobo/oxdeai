/**
 * pep.ts — Policy Enforcement Point (PEP)
 *
 * Mirrors examples/openai-tools:
 *   - PDP evaluates intent
 *   - PEP executes tool only on ALLOW with Authorization present
 */

import type { Authorization, State } from "@oxdeai/core";
import { buildProvisionIntent, engine, gpuCost } from "./policy.js";

let provisionCounter = 0;

function provision_gpu(asset: string, region: string): string {
  provisionCounter += 1;
  return `${asset}-${region}-${provisionCounter.toString(36)}`;
}

export type GuardedResult =
  | { allowed: true; instanceId: string; authorization: Authorization; nextState: State }
  | { allowed: false; reasons: string[] };

export function guardedProvision(
  asset: string,
  region: string,
  state: State,
  timestampSeconds: number,
  log: (msg: string) => void
): GuardedResult {
  const cost = gpuCost(asset, region);
  const intent = buildProvisionIntent(asset, region, timestampSeconds);

  log(`\n┌─ Proposed tool call`);
  log(`│  provision_gpu(asset=${asset}, region=${region})`);
  log(`│  cost=${cost} minor units  nonce=${intent.nonce}  intent_id=${intent.intent_id}`);

  const result = engine.evaluatePure(intent, state);
  if (result.decision === "DENY") {
    const reasons = result.reasons ?? ["unknown"];
    log(`└─ DENY  reasons: ${reasons.join(", ")}`);
    return { allowed: false, reasons };
  }

  const authorization = result.authorization;
  if (!authorization) {
    throw new Error(`PEP invariant violated: ALLOW with no Authorization for ${intent.intent_id}`);
  }

  log(`│  ALLOW  auth_id=${authorization.authorization_id.slice(0, 16)}...`);
  log(`│         expires=${authorization.expires_at}  state_hash=${authorization.state_snapshot_hash.slice(0, 16)}...`);

  const instanceId = provision_gpu(asset, region);
  log(`└─ EXECUTED  instance_id=${instanceId}`);

  if (!result.nextState) {
    throw new Error(`PDP returned ALLOW but no nextState for ${intent.intent_id}`);
  }
  return { allowed: true, instanceId, authorization, nextState: result.nextState };
}
