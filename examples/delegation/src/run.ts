/**
 * run.ts — DelegationV1 Demo
 *
 * Scenario:
 *   parent-agent holds full authority (ALLOW authorization from PDP).
 *   parent delegates LIMITED scope to child-agent:
 *     tools=[provision_gpu], max_amount=300n units, expiry=now+60s
 *
 *   child call 1: provision_gpu, amount=200  → ALLOW  (within scope)
 *   child call 2: provision_gpu, amount=200  → ALLOW  (within scope)
 *   child call 3: query_db,      amount=200  → DENY   (tool not in delegation scope)
 *   child call 4: provision_gpu, amount=200  → DENY   (delegation expired)
 *
 * Uses @oxdeai/core — no inline implementation.
 *
 * Usage:
 *   pnpm -C examples/delegation start
 */

import { pathToFileURL } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import {
  signAuthorizationEd25519,
  createDelegation,
  verifyDelegationChain,
  delegationParentHash,
  type AuthorizationV1,
  type DelegationV1,
  type KeySet,
} from "@oxdeai/core";

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  bCyan:   "\x1b[1;36m",
  green:   "\x1b[32m",
  bGreen:  "\x1b[1;32m",
  red:     "\x1b[31m",
  bRed:    "\x1b[1;31m",
  yellow:  "\x1b[33m",
  white:   "\x1b[97m",
  bWhite:  "\x1b[1;97m",
  magenta: "\x1b[35m",
};

const c = (col: string, t: string) => `${col}${t}${C.reset}`;

// ── Demo constants ────────────────────────────────────────────────────────────

const POLICY_ID    = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const PARENT_AGENT = "parent-agent";
const CHILD_AGENT  = "child-agent";
const KID          = "demo-key-1";

// ── Entry point ───────────────────────────────────────────────────────────────

async function runDemo(log = (m: string) => console.log(m)): Promise<void> {
  // All timestamps in unix seconds
  const T_NOW     = Math.floor(Date.now() / 1000);
  const T_ISSUED  = T_NOW - 60;
  const T_PAR_EXP = T_NOW + 3600;  // parent auth expires in 1 hour
  const T_DEL_EXP = T_NOW + 60;    // delegation expires in 60s
  const T_EXPIRED = T_NOW - 5;     // already-expired delegation

  // ── Header ────────────────────────────────────────────────────────────────
  log(c(C.cyan,  "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan,  "║") + c(C.bWhite, "  OxDeAI — DelegationV1 Demo                                    ") + c(C.cyan, "║"));
  log(c(C.cyan,  "║") + c(C.dim,    "  Parent delegates narrowed authority to child agent             ") + c(C.cyan, "║"));
  log(c(C.cyan,  "╚══════════════════════════════════════════════════════════════════╝"));

  // ── Step 1: Generate signing key pair ─────────────────────────────────────
  // In production: the parent agent holds this key pair, issued by a key authority.
  // The same key is registered in the parent's KeySet so delegation signatures can
  // be verified at the PEP without a control-plane call.
  log(`\n${c(C.dim, "── Setup ────────────────────────────────────────────────────────────")}`);
  const keys = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding:  { format: "pem", type: "spki" },
  });
  log(`   ${c(C.dim, "key:")}    ${c(C.bCyan, KID)} (Ed25519, demo-only)`);

  // KeySet for delegation signature verification.
  // issuer = parent.audience = PARENT_AGENT (the delegating principal, not the PDP).
  const keySet: KeySet = {
    issuer: PARENT_AGENT,
    version: "1",
    keys: [{ kid: KID, alg: "Ed25519", public_key: keys.publicKey }],
  };

  // ── Step 2: Parent AuthorizationV1 ────────────────────────────────────────
  // In production: produced by PolicyEngine.evaluatePure() after PDP evaluation.
  // Here: constructed directly to isolate the delegation layer.
  const parentAuth: AuthorizationV1 = signAuthorizationEd25519(
    {
      auth_id:     "f".repeat(64),
      issuer:      "oxdeai-pdp",
      audience:    PARENT_AGENT,
      intent_hash: "a".repeat(64),
      state_hash:  "b".repeat(64),
      policy_id:   POLICY_ID,
      decision:    "ALLOW",
      issued_at:   T_ISSUED,
      expiry:      T_PAR_EXP,
      kid:         KID,
    },
    keys.privateKey
  );

  log(`\n${c(C.dim, "── Parent authorization ─────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "agent:")}   ${c(C.bCyan, PARENT_AGENT)}`);
  log(`   ${c(C.dim, "auth:")}    ${c(C.yellow, parentAuth.decision)} (issued by ${c(C.dim, parentAuth.issuer)})`);
  log(`   ${c(C.dim, "hash:")}    ${c(C.dim, delegationParentHash(parentAuth).slice(0, 32) + "...")}`);

  // ── Step 3: Create delegation for child agent ─────────────────────────────
  // Scope is strictly narrowed from parent: only provision_gpu, max 300 units.
  const delegation: DelegationV1 = createDelegation(
    parentAuth,
    {
      delegatee:  CHILD_AGENT,
      scope:      { tools: ["provision_gpu"], max_amount: 300n },
      expiry:     T_DEL_EXP,
      kid:        KID,
    },
    keys.privateKey
  );

  // Properly signed delegation that is already expired (for scenario 4)
  const expiredDelegation: DelegationV1 = createDelegation(
    parentAuth,
    {
      delegatee:  CHILD_AGENT,
      scope:      { tools: ["provision_gpu"], max_amount: 300n },
      expiry:     T_EXPIRED,
      kid:        KID,
      issuedAt:   T_ISSUED - 10,
    },
    keys.privateKey
  );

  log(`\n${c(C.dim, "── Delegation created ───────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "from:")}    ${c(C.bCyan, PARENT_AGENT)} → ${c(C.magenta, CHILD_AGENT)}`);
  log(`   ${c(C.dim, "tools:")}   ${c(C.yellow, delegation.scope.tools?.join(", ") ?? "(any)")} ${c(C.dim, "(query_db excluded)")}`);
  log(`   ${c(C.dim, "budget:")}  ${c(C.yellow, String(delegation.scope.max_amount ?? "(unlimited)"))} units max`);
  log(`   ${c(C.dim, "expiry:")}  60 seconds`);
  log(`   ${c(C.dim, "id:")}      ${c(C.dim, delegation.delegation_id.slice(0, 24) + "...")}`);

  // ── Step 4: Child executes actions ────────────────────────────────────────

  type Scenario = {
    label:         string;
    tool:          string;
    amount:        bigint;
    useDelegation: DelegationV1;
    now:           number;
  };

  const scenarios: Scenario[] = [
    {
      label:         "provision_gpu / amount=200",
      tool:          "provision_gpu",
      amount:        200n,
      useDelegation: delegation,
      now:           T_NOW,
    },
    {
      label:         "provision_gpu / amount=200",
      tool:          "provision_gpu",
      amount:        200n,
      useDelegation: delegation,
      now:           T_NOW,
    },
    {
      label:         "query_db / amount=200",
      tool:          "query_db",
      amount:        200n,
      useDelegation: delegation,
      now:           T_NOW,
    },
    {
      label:         "provision_gpu / amount=200 (expired delegation)",
      tool:          "provision_gpu",
      amount:        200n,
      useDelegation: expiredDelegation,
      now:           T_NOW,
    },
  ];

  log(`\n${c(C.dim, "── Child agent proposals ────────────────────────────────────────────")}`);

  const decisions: string[] = [];

  for (const s of scenarios) {
    // 1. Verify delegation chain integrity (signature, expiry, hash binding, etc.)
    const chain = verifyDelegationChain(s.useDelegation, parentAuth, {
      now:                        s.now,
      expectedDelegatee:          CHILD_AGENT,
      trustedKeySets:             keySet,
      requireSignatureVerification: true,
    });

    // 2. If chain is valid, enforce scope at the action level
    let decision: "ALLOW" | "DENY" = "ALLOW";
    let reason = "";

    if (!chain.ok) {
      decision = "DENY";
      reason = chain.violations.map((v) => v.message).join("; ");
    } else {
      const tools = s.useDelegation.scope.tools;
      if (tools && !tools.includes(s.tool)) {
        decision = "DENY";
        reason = `tool '${s.tool}' not in delegation scope: [${tools.join(", ")}]`;
      } else if (
        s.useDelegation.scope.max_amount !== undefined &&
        s.amount > s.useDelegation.scope.max_amount
      ) {
        decision = "DENY";
        reason = `amount ${s.amount} exceeds delegation max_amount ${s.useDelegation.scope.max_amount}`;
      }
    }

    log(`\n┌─ ${c(C.dim, "Child proposes:")} ${s.label}`);

    if (decision === "ALLOW") {
      decisions.push("ALLOW");
      log(`│  ${c(C.bGreen, "ALLOW")}  delegation verified`);
      log(`└─ ${c(C.dim, "EXECUTED:")} ${s.tool}(amount=${s.amount})`);
    } else {
      decisions.push("DENY");
      log(`│  ${c(C.bRed, "DENY")}   ${reason}`);
      log(`└─ ${c(C.dim, "BLOCKED — tool did not execute")}`);
    }
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  log(`\n${c(C.dim, "── Summary ──────────────────────────────────────────────────────────")}`);
  log(`   Allowed: ${c(C.bGreen, String(decisions.filter(d => d === "ALLOW").length))}   Denied: ${c(C.bRed, String(decisions.filter(d => d === "DENY").length))}`);

  log(`\n${c(C.dim, "── Decisions ────────────────────────────────────────────────────────")}`);
  decisions.forEach((d, i) => {
    const col = d === "ALLOW" ? c(C.bGreen, d) : c(C.bRed, d);
    log(`   call ${i + 1}: ${col}`);
  });

  // ── What just happened ────────────────────────────────────────────────────
  log("");
  log(c(C.bGreen, "✓ Delegation demo complete."));
  log("");
  log(`  ${c(C.bWhite, "What just happened:")}`);
  log(`  ${c(C.cyan, "┌─────────────────────────────────────────────────────────────────┐")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PARENT")}  Received ALLOW from PDP (AuthorizationV1).              ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}         Delegated ${c(C.yellow, "narrowed")} scope to child — 1 tool, 300 units. ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "CHILD")}   Called provision_gpu twice → ${c(C.bGreen, "ALLOW")} (within scope).     ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}         Called query_db → ${c(C.bRed, "DENY")} (tool not in delegation).        ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}         Called with expired delegation → ${c(C.bRed, "DENY")}.                   ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}                                                                 ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "KEY")}     Scope narrowing is enforced locally. No control plane.  ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "│")}         Delegation is cryptographically bound to parent auth.  ${c(C.cyan, "│")}`);
  log(`  ${c(C.cyan, "└─────────────────────────────────────────────────────────────────┘")}`);
}

// ── Run ───────────────────────────────────────────────────────────────────────

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) {
  runDemo().catch((err) => {
    console.error(`\n${"\x1b[1;31m"}✗ Demo failed:${"\x1b[0m"}`, err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
