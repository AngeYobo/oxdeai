/**
 * run.ts - Terminal two-panel visualization of the delegation demo.
 *
 * Renders the delegation scenario in the terminal:
 *   Left panel:  Agent Logs (Agent A principal + Agent B delegated)
 *   Right panel: Authorization Decisions (engine auth + delegation verification)
 *
 * Clears and redraws the screen on each step. Auto-loops.
 * ALLOW / DENY badges use software blinking (450ms toggle).
 *
 * Usage: pnpm -C examples/delegation-demo terminal
 */

import { pathToFileURL } from "node:url";
import { runScenario } from "./scenario.js";
import type { ScenarioStep } from "./scenario.js";

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  yellow:  "\x1b[33m",
  magenta: "\x1b[35m",
  bCyan:   "\x1b[1;36m",
  bGreen:  "\x1b[1;32m",
  bRed:    "\x1b[1;31m",
  bYellow: "\x1b[1;33m",
  bMagenta:"\x1b[1;35m",
  bWhite:  "\x1b[1;97m",
};
const c = (col: string, txt: string) => `${col}${txt}${C.reset}`;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

// ── Layout ────────────────────────────────────────────────────────────────────
const W   = Math.max(86, (process.stdout.columns ?? 120) - 2);
const COL = Math.floor((W - 7) / 2);

function vlen(s: string): number {
  return s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "").length;
}
function pad(s: string, width: number): string {
  return s + " ".repeat(Math.max(0, width - vlen(s)));
}
function center(s: string, width: number): string {
  const total = Math.max(0, width - vlen(s));
  const l = Math.floor(total / 2);
  return " ".repeat(l) + s + " ".repeat(total - l);
}

// ── Box primitives ────────────────────────────────────────────────────────────
const TOP = c(C.cyan, "╔" + "═".repeat(W - 2) + "╗");
const MID = c(C.cyan, "╠" + "═".repeat(W - 2) + "╣");
const DIV = c(C.cyan, "╟" + "─".repeat(W - 2) + "╢");
const BOT = c(C.cyan, "╚" + "═".repeat(W - 2) + "╝");

function row(left: string, right: string): string {
  return (
    c(C.cyan, "║") + " " +
    pad(left,  COL) + " " +
    c(C.dim, "│") + " " +
    pad(right, COL) + " " +
    c(C.cyan, "║")
  );
}
function full(text: string): string {
  return c(C.cyan, "║") + " " + pad(text, W - 4) + " " + c(C.cyan, "║");
}

// ── Agent prefix ──────────────────────────────────────────────────────────────
function agentPrefix(agentId: "A" | "B"): string {
  return agentId === "A"
    ? c(C.bCyan,    "[A]")
    : c(C.bMagenta, "[B]");
}

// ── Step → display rows ───────────────────────────────────────────────────────

interface DisplayRow { left: string; right: string }

function toDisplayRows(steps: ScenarioStep[], reveal: number, blinkOn: boolean): DisplayRow[] {
  const rows: DisplayRow[] = [];

  for (let i = 0; i < Math.min(reveal, steps.length); i++) {
    const step = steps[i]!;
    const { agentId, type, label, detail } = step.agent;

    const ICON: Record<string, string> = {
      thought: "◆", propose: "→", execute: "✓", blocked: "✗", delegate: "⇢",
    };
    const icon = ICON[type] ?? " ";
    const prefix = agentPrefix(agentId);

    // Agent (left)
    let leftMain: string;
    let leftSub = "";

    if (type === "thought") {
      leftMain = c(C.dim, `${icon} ${prefix} ${label}`.slice(0, COL - 1));
      if (detail) leftSub = c(C.dim, `    ${detail.slice(0, COL - 4)}`);
    } else if (type === "propose") {
      const col = agentId === "A" ? C.cyan : C.magenta;
      leftMain = c(col, `${icon} ${prefix} ${label}`.slice(0, COL - 1));
      if (detail) leftSub = c(C.dim, `    ${detail.slice(0, COL - 4)}`);
    } else if (type === "delegate") {
      leftMain = c(C.yellow, `${icon} ${prefix} ${label}`.slice(0, COL - 1));
      if (detail) leftSub = c(C.dim, `    ${detail.slice(0, COL - 4)}`);
    } else if (type === "execute") {
      const col = agentId === "A" ? C.green : C.bGreen;
      leftMain = c(col, `${icon} ${prefix} ${label}`.slice(0, COL - 1));
      if (detail) leftSub = c(C.dim, `    ${detail.slice(0, COL - 4)}`);
    } else if (type === "blocked") {
      leftMain = c(C.red, `${icon} ${prefix} ${label}`.slice(0, COL - 1));
      if (detail) leftSub = c(C.dim, `    ${detail.slice(0, COL - 4)}`);
    } else {
      leftMain = `${icon} ${label}`;
    }

    // Authorization (right)
    let rightMain = "";
    let rightSub  = "";
    let rightSub2 = "";

    if (step.auth) {
      const { decision, reason, authType, authId, delegationId, amountUnits, maxUnits, executionStatus } = step.auth;
      const idLabel = authType === "engine" ? authId : delegationId;
      const idShort = idLabel ? idLabel.slice(0, 18) + "…" : "";
      const idTag   = authType === "engine" ? "auth" : "deleg";

      if (decision === "ALLOW") {
        rightMain = blinkOn
          ? c(C.bGreen, "✓ ALLOW") + "  " + c(C.dim, authType === "engine" ? "via engine" : "via delegation")
          : "              " + c(C.dim, authType === "engine" ? "via engine" : "via delegation");
        rightSub  = c(C.dim, `  ${idTag}: ${idShort}`);
        if (maxUnits !== undefined) {
          const amtStr = `${amountUnits} of max ${maxUnits}  ·  within scope`;
          rightSub2 = c(C.green, `  ${amtStr.slice(0, COL - 2)}`);
        }
      } else {
        const reasonShort = reason.slice(0, COL - 10);
        rightMain = blinkOn
          ? c(C.bRed, "✗ DENY") + "  " + c(C.red, reasonShort)
          : "        " + c(C.dim, reasonShort);
        rightSub  = c(C.dim, `  ${idTag}: ${idShort}`);
        if (maxUnits !== undefined) {
          rightSub2 = c(C.red, `  ${amountUnits} > max ${maxUnits}  ·  scope exceeded`);
        }
      }

      if (executionStatus !== "not_applicable") {
        const execLine = executionStatus === "executed"
          ? c(C.green, "  executed  ·  side effect committed")
          : c(C.red,   "  tool not invoked  ·  no side effect");
        rows.push({ left: leftMain,  right: rightMain });
        rows.push({ left: leftSub,   right: rightSub });
        if (rightSub2) rows.push({ left: "",       right: rightSub2 });
        rows.push({ left: "",        right: execLine });
        continue;
      } else {
        // Delegation issuance — no execution line
        rows.push({ left: leftMain, right: rightMain });
        rows.push({ left: leftSub,  right: rightSub });
        if (rightSub2) rows.push({ left: "", right: rightSub2 });
        continue;
      }
    }

    rows.push({ left: leftMain, right: rightMain });
    if (leftSub || rightSub) {
      rows.push({ left: leftSub, right: rightSub });
    }
  }

  return rows;
}

// ── Render one frame ──────────────────────────────────────────────────────────

const MIN_CONTENT_ROWS = 16;

function render(
  steps:              ScenarioStep[],
  reveal:             number,
  parentAuthGranted:  boolean,
  delegationActive:   boolean,
  delegationScope:    string,
  loopCount:          number,
  blinkOn:            boolean,
): void {
  const out: string[] = [];

  out.push("\x1b[2J\x1b[H");

  out.push(TOP);
  out.push(full(center(c(C.bWhite, "OxDeAI  -  Delegation Demo"), W - 4)));
  out.push(full(c(C.dim, "  Agent A delegates narrowed authority  ·  Agent B cannot exceed delegated scope")));
  out.push(MID);
  out.push(row(
    c(C.bCyan, "AGENT LOGS") + "  " + c(C.dim, "[A]=principal  [B]=delegated"),
    c(C.bCyan, "AUTHORIZATION")
  ));
  out.push(MID);

  const drows = toDisplayRows(steps, reveal, blinkOn);
  const total = Math.max(MIN_CONTENT_ROWS, drows.length);
  for (let i = 0; i < total; i++) {
    const dr = drows[i] ?? { left: "", right: "" };
    out.push(row(dr.left, dr.right));
  }

  out.push(DIV);

  const authColor  = parentAuthGranted ? C.green  : C.dim;
  const delegColor = delegationActive  ? C.yellow : C.dim;
  out.push(row(
    `  parent_auth:  ${c(authColor,  parentAuthGranted ? "granted  ✓" : "pending")}`,
    `delegation_scope:  ${c(delegColor, delegationScope)}`,
  ));

  out.push(BOT);
  out.push(loopCount > 1
    ? c(C.dim, `  loop ${loopCount}  ·  ^C to exit`)
    : c(C.dim, "  ^C to exit"),
  );

  process.stdout.write(out.join("\n") + "\n");
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run(): Promise<void> {
  const STEP_MS  = 1500;
  const LOOP_MS  = 8000;
  const BLINK_MS = 450;

  const steps = await runScenario();

  process.stdout.write("\x1b[?25l");
  const cleanup = () => {
    process.stdout.write("\x1b[?25h\x1b[2J\x1b[H");
    process.exit(0);
  };
  process.on("SIGINT",  cleanup);
  process.on("SIGTERM", cleanup);

  let blinkOn          = true;
  let revealRef        = 0;
  let parentAuthRef    = false;
  let delegActiveRef   = false;
  let delegScopeRef    = "—";
  let loopCountRef     = 0;

  const blinkTick = setInterval(() => {
    blinkOn = !blinkOn;
    render(steps, revealRef, parentAuthRef, delegActiveRef, delegScopeRef, loopCountRef, blinkOn);
  }, BLINK_MS);

  while (true) {
    loopCountRef++;
    parentAuthRef  = false;
    delegActiveRef = false;
    delegScopeRef  = "—";

    for (let reveal = 0; reveal <= steps.length; reveal++) {
      revealRef = reveal;
      blinkOn   = true;
      render(steps, reveal, parentAuthRef, delegActiveRef, delegScopeRef, loopCountRef, blinkOn);
      await sleep(STEP_MS);

      const just = steps[reveal - 1];
      if (just?.stateAfter) {
        parentAuthRef  = just.stateAfter.parentAuthGranted;
        delegActiveRef = just.stateAfter.delegationActive;
        delegScopeRef  = just.stateAfter.delegationScope;
      }
    }

    await sleep(LOOP_MS);
  }

  // eslint-disable-next-line no-unreachable
  clearInterval(blinkTick);
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  run().catch(err => {
    process.stdout.write("\x1b[?25h");
    console.error(`\x1b[1;31m✗ Terminal demo failed:\x1b[0m`, err);
    process.exit(1);
  });
}
