import type { Authorization, State } from "@oxdeai/core";
import { buildProvisionIntent, engine, gpuCost } from "./policy.js";

const C = {
  reset:      "\x1b[0m",
  bold:       "\x1b[1m",
  dim:        "\x1b[2m",
  cyan:       "\x1b[36m",
  green:      "\x1b[32m",
  red:        "\x1b[31m",
  yellow:     "\x1b[33m",
  blue:       "\x1b[34m",
  magenta:    "\x1b[35m",
  white:      "\x1b[97m",
  bCyan:      "\x1b[1;36m",
  bGreen:     "\x1b[1;32m",
  bRed:       "\x1b[1;31m",
  bYellow:    "\x1b[1;33m",
  bWhite:     "\x1b[1;97m",
  bMagenta:   "\x1b[1;35m",
};

const c = (color: string, text: string) => `${color}${text}${C.reset}`;

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

  log(`\n${c(C.dim, "┌─ Proposed tool call")}`);
  log(`${c(C.dim, "│")}  ${c(C.bWhite, "provision_gpu")}(asset=${asset}, region=${region})`);
  log(`${c(C.dim, "│")}  cost=${c(C.yellow, String(cost))} minor units  nonce=${intent.nonce}  intent_id=${intent.intent_id}`);

  const result = engine.evaluatePure(intent, state);
  if (result.decision === "DENY") {
    const reasons = result.reasons ?? ["unknown"];
    log(`${c(C.bRed, "└─ DENY")}  reasons: ${c(C.bYellow, reasons.join(", "))}`);
    return { allowed: false, reasons };
  }

  const authorization = result.authorization;
  if (!authorization) {
    throw new Error(`PEP invariant violated: ALLOW with no Authorization for ${intent.intent_id}`);
  }

  log(`${c(C.dim, "│")}  ${c(C.bGreen, "ALLOW")}  auth_id=${c(C.blue, authorization.authorization_id.slice(0, 16) + "...")}`);
  log(`${c(C.dim, "│")}         expires=${authorization.expires_at}  state_hash=${c(C.cyan, authorization.state_snapshot_hash.slice(0, 16) + "...")}`);

  const instanceId = provision_gpu(asset, region);
  log(`${c(C.bGreen, "└─ EXECUTED")}  instance_id=${c(C.cyan, instanceId)}`);

  if (!result.nextState) {
    throw new Error(`PDP returned ALLOW but no nextState for ${intent.intent_id}`);
  }
  return { allowed: true, instanceId, authorization, nextState: result.nextState };
}
