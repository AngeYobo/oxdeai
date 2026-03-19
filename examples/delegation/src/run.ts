/**
 * run.ts — DelegationV1 Demo
 *
 * Scenario:
 *   parent-agent holds full authority: tools=[provision_gpu, query_db], budget=1000
 *   parent delegates LIMITED scope to child-agent:
 *     tools=[provision_gpu], max_amount=300, expiry=now+60s
 *
 *   child call 1: provision_gpu, amount=200  → ALLOW  (within scope)
 *   child call 2: provision_gpu, amount=200  → ALLOW  (within scope)
 *   child call 3: query_db,      amount=200  → DENY   (tool not in delegation)
 *   child call 4: provision_gpu, amount=200  → DENY   (delegation expired)
 *
 * Usage:
 *   pnpm -C examples/delegation start
 */

import { pathToFileURL } from "node:url";
import {
  generateDemoKeyPair,
  createDelegation,
  verifyDelegation,
  hashParentAuth,
  type ParentAuth,
  type DelegationScope,
} from "./delegation.js";

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

// ── Entry point ───────────────────────────────────────────────────────────────

async function runDemo(log = (m: string) => console.log(m)): Promise<void> {
  const now = Date.now();

  // ── Header ────────────────────────────────────────────────────────────────
  log(c(C.cyan,  "╔══════════════════════════════════════════════════════════════════╗"));
  log(c(C.cyan,  "║") + c(C.bWhite, "  OxDeAI — DelegationV1 Demo                                    ") + c(C.cyan, "║"));
  log(c(C.cyan,  "║") + c(C.dim,    "  Parent delegates narrowed authority to child agent             ") + c(C.cyan, "║"));
  log(c(C.cyan,  "╚══════════════════════════════════════════════════════════════════╝"));

  // ── Step 1: Generate signing key pair ─────────────────────────────────────
  log(`\n${c(C.dim, "── Setup ────────────────────────────────────────────────────────────")}`);
  const keyPair = generateDemoKeyPair("demo-key-1");
  log(`   ${c(C.dim, "key:")}    ${c(C.bCyan, keyPair.kid)} (Ed25519, demo-only)`);

  // ── Step 2: Parent AuthorizationV1 (simulated PDP output) ─────────────────
  // In production: produced by engine.evaluatePure() after policy evaluation.
  // Here: constructed directly to isolate the delegation layer.

  const parentAuth: ParentAuth = {
    auth_id:       "auth-parent-001",
    issuer:        "oxdeai-pdp",
    audience:      PARENT_AGENT,
    policy_id:     POLICY_ID,
    allowed_tools: ["provision_gpu", "query_db"],
    max_amount:    1000,
    expiry:        now + 3_600_000,  // 1 hour
  };

  log(`\n${c(C.dim, "── Parent authorization ─────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "agent:")}   ${c(C.bCyan, PARENT_AGENT)}`);
  log(`   ${c(C.dim, "tools:")}   ${c(C.yellow, parentAuth.allowed_tools.join(", "))}`);
  log(`   ${c(C.dim, "budget:")}  ${c(C.yellow, String(parentAuth.max_amount))} units`);
  log(`   ${c(C.dim, "hash:")}    ${c(C.dim, hashParentAuth(parentAuth).slice(0, 32) + "...")}`);

  // ── Step 3: Create delegation for child agent ─────────────────────────────
  const delegationScope: DelegationScope = {
    tools:      ["provision_gpu"],   // query_db excluded — narrowed
    max_amount: 300,                  // 1000 → 300 — narrowed
  };

  const delegation = createDelegation(
    parentAuth,
    CHILD_AGENT,
    delegationScope,
    now + 60_000,   // expires in 60s
    keyPair,
    now
  );

  // Properly signed delegation with expiry already in the past (for scenario 4)
  const expiredDelegation = createDelegation(
    parentAuth,
    CHILD_AGENT,
    delegationScope,
    now - 5_000,    // expired 5s ago
    keyPair,
    now - 10_000    // issued 10s ago
  );

  log(`\n${c(C.dim, "── Delegation created ───────────────────────────────────────────────")}`);
  log(`   ${c(C.dim, "from:")}    ${c(C.bCyan, PARENT_AGENT)} → ${c(C.magenta, CHILD_AGENT)}`);
  log(`   ${c(C.dim, "tools:")}   ${c(C.yellow, delegation.scope.tools.join(", "))} ${c(C.dim, "(query_db excluded)")}`);
  log(`   ${c(C.dim, "budget:")}  ${c(C.yellow, String(delegation.scope.max_amount))} units max ${c(C.dim, "(was 1000)")}`);
  log(`   ${c(C.dim, "expiry:")}  60 seconds`);
  log(`   ${c(C.dim, "id:")}      ${c(C.dim, delegation.delegation_id.slice(0, 24) + "...")}`);

  // ── Step 4: Child executes actions ────────────────────────────────────────

  const decisions: string[] = [];

  const scenarios: Array<{
    label:         string;
    tool:          string;
    amount:        number;
    useDelegation: typeof delegation;
    now:           number;
    expectNote:    string;
  }> = [
    {
      label:         "provision_gpu / amount=200",
      tool:          "provision_gpu",
      amount:        200,
      useDelegation: delegation,
      now,
      expectNote:    "within scope",
    },
    {
      label:         "provision_gpu / amount=200",
      tool:          "provision_gpu",
      amount:        200,
      useDelegation: delegation,
      now,
      expectNote:    "within scope",
    },
    {
      label:         "query_db / amount=200",
      tool:          "query_db",
      amount:        200,
      useDelegation: delegation,
      now,
      expectNote:    "tool not in delegation scope",
    },
    {
      label:         "provision_gpu / amount=200 (expired delegation)",
      tool:          "provision_gpu",
      amount:        200,
      useDelegation: expiredDelegation,
      now,
      expectNote:    "delegation expired",
    },
  ];

  log(`\n${c(C.dim, "── Child agent proposals ────────────────────────────────────────────")}`);

  for (const s of scenarios) {
    const result = verifyDelegation(
      s.useDelegation,
      parentAuth,
      CHILD_AGENT,
      s.tool,
      s.amount,
      keyPair.publicKeyPem,
      s.now
    );

    log(`\n┌─ ${c(C.dim, "Child proposes:")} ${s.label}`);

    if (result.ok) {
      decisions.push("ALLOW");
      log(`│  ${c(C.bGreen, "ALLOW")}  delegation verified`);
      log(`└─ ${c(C.dim, "EXECUTED:")} ${s.tool}(amount=${s.amount})`);
    } else {
      decisions.push("DENY");
      log(`│  ${c(C.bRed, "DENY")}   ${result.reason}`);
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
  log(`  ${c(C.cyan, "│")} ${c(C.bCyan, "PARENT")}  Held full authority: tools + 1000-unit budget.           ${c(C.cyan, "│")}`);
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
    console.error(`\n${"\x1b[1;31m"}✗ Demo failed:${"\x1b[0m"}`, err);
    process.exit(1);
  });
}
