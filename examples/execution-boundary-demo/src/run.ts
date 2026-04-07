// SPDX-License-Identifier: Apache-2.0
/**
 * run.ts - Terminal two-panel visualization of the execution boundary demo.
 *
 * Renders the same scenario as the browser demo but in the terminal:
 *   Left panel:  Agent Logs
 *   Right panel: Authorization Decisions (PDP)
 *
 * Clears and redraws the screen on each step. Auto-loops.
 * ALLOW / DENY badges use software blinking (450ms toggle).
 *
 * Usage: pnpm -C examples/execution-boundary-demo terminal
 */

import { pathToFileURL } from "node:url";
import { runScenario } from "./scenario.js";
import type { ScenarioStep } from "./scenario.js";

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const C = {
  reset:  "\x1b[0m",
  dim:    "\x1b[2m",
  cyan:   "\x1b[36m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  bCyan:  "\x1b[1;36m",
  bGreen: "\x1b[1;32m",
  bRed:   "\x1b[1;31m",
  bWhite: "\x1b[1;97m",
};
const c = (col: string, txt: string) => `${col}${txt}${C.reset}`;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

// ── Layout (adapts to terminal width) ────────────────────────────────────────
const W   = Math.max(82, (process.stdout.columns ?? 120) - 2);
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

// ── Step → display rows ───────────────────────────────────────────────────────

interface DisplayRow { left: string; right: string }

function toDisplayRows(steps: ScenarioStep[], reveal: number, blinkOn: boolean): DisplayRow[] {
  const rows: DisplayRow[] = [];

  for (let i = 0; i < Math.min(reveal, steps.length); i++) {
    const step = steps[i]!;
    const { type, label, detail } = step.agent;

    const ICON: Record<string, string> = {
      thought: "◆", propose: "→", execute: "✓", blocked: "✗",
    };
    const icon = ICON[type] ?? " ";

    // Agent (left)
    let leftMain: string;
    let leftSub = "";

    if (type === "thought") {
      leftMain = c(C.dim, `${icon} ${label}`);
      if (detail) leftSub = c(C.dim, `  ${detail.slice(0, COL - 2)}`);
    } else if (type === "propose") {
      leftMain = c(C.cyan, `${icon} ${label.slice(0, COL - 3)}`);
      if (detail) leftSub = c(C.dim, `  ${detail.slice(0, COL - 2)}`);
    } else if (type === "execute") {
      leftMain = c(C.green, `${icon} ${label}`);
      if (detail) leftSub = c(C.dim, `  ${detail.slice(0, COL - 2)}`);
    } else if (type === "blocked") {
      leftMain = c(C.red, `${icon} ${label}`);
      if (detail) leftSub = c(C.dim, `  ${detail.slice(0, COL - 2)}`);
    } else {
      leftMain = `${icon} ${label}`;
    }

    // Authorization (right) - badge blinks via software toggle
    let rightMain = "";
    let rightSub  = "";

    if (step.auth) {
      const { decision, reason, intentId, executionStatus } = step.auth;
      if (decision === "ALLOW") {
        rightMain = blinkOn
          ? c(C.bGreen, "✓ ALLOW")
          : "       ";  // 7 spaces = vlen("✓ ALLOW")
        rightSub = c(C.dim, `  intent: ${intentId.slice(0, COL - 10)}`);
      } else {
        const reasonShort = reason.slice(0, COL - 10);
        rightMain = blinkOn
          ? c(C.bRed, "✗ DENY") + "  " + c(C.red, reasonShort)
          : "        " + c(C.dim, reasonShort);
        rightSub = c(C.dim, `  intent: ${intentId.slice(0, COL - 10)}`);
      }
      // Execution status row - explicit "tool not invoked" on DENY
      const execLine = executionStatus === "executed"
        ? c(C.green,  "  executed  ·  side effect committed")
        : c(C.red,    "  tool not invoked  ·  no side effect");
      rows.push({ left: leftMain, right: rightMain });
      rows.push({ left: leftSub,  right: rightSub });
      rows.push({ left: "",       right: execLine });
      continue;
    }

    rows.push({ left: leftMain, right: rightMain });
    if (leftSub || rightSub) {
      rows.push({ left: leftSub, right: rightSub });
    }
  }

  return rows;
}

// ── Render one frame ──────────────────────────────────────────────────────────

const MIN_CONTENT_ROWS = 14;

function render(
  steps:          ScenarioStep[],
  reveal:         number,
  walletBalance:  string,
  alreadyCharged: boolean,
  loopCount:      number,
  blinkOn:        boolean,
): void {
  const out: string[] = [];

  out.push("\x1b[2J\x1b[H");

  out.push(TOP);
  out.push(full(center(c(C.bWhite, "OxDeAI  -  Execution Boundary Demo"), W - 4)));
  out.push(full(c(C.dim, "  same intent  ·  changed state  →  different authorization decision")));
  out.push(MID);
  out.push(row(c(C.bCyan, "AGENT"), c(C.bCyan, "AUTHORIZATION (PDP)")));
  out.push(MID);

  const drows = toDisplayRows(steps, reveal, blinkOn);
  const total = Math.max(MIN_CONTENT_ROWS, drows.length);
  for (let i = 0; i < total; i++) {
    const dr = drows[i] ?? { left: "", right: "" };
    out.push(row(dr.left, dr.right));
  }

  out.push(DIV);

  const balColor = alreadyCharged ? C.yellow : C.dim;
  const chgColor = alreadyCharged ? C.bGreen : C.dim;
  out.push(row(
    `  wallet_balance: ${c(balColor, walletBalance)}`,
    `already_charged: ${c(chgColor, alreadyCharged ? "true  ✓" : "false")}`,
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
  const STEP_MS  = 1400;
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

  // Shared state - read by the blink ticker between step advances
  let blinkOn        = true;
  let revealRef      = 0;
  let walletRef      = "100.00";
  let chargedRef     = false;
  let loopCountRef   = 0;

  // Independent blink ticker: toggles badge every 450ms and redraws
  const blinkTick = setInterval(() => {
    blinkOn = !blinkOn;
    render(steps, revealRef, walletRef, chargedRef, loopCountRef, blinkOn);
  }, BLINK_MS);

  while (true) {
    loopCountRef++;
    walletRef  = "100.00";
    chargedRef = false;

    for (let reveal = 0; reveal <= steps.length; reveal++) {
      revealRef = reveal;
      blinkOn   = true;  // start blink cycle fresh on each step
      render(steps, reveal, walletRef, chargedRef, loopCountRef, blinkOn);
      await sleep(STEP_MS);

      const just = steps[reveal - 1];
      if (just?.stateAfter) {
        walletRef  = just.stateAfter.walletBalance;
        chargedRef = just.stateAfter.alreadyCharged;
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
    console.error(`\x1b[1;31m✗ Terminal demo failed:\x1b[0m`, err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
