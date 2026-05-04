// SPDX-License-Identifier: Apache-2.0
// Terminal display utilities. Zero external dependencies.

const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
  blue:   "\x1b[34m",
  gray:   "\x1b[90m",
  white:  "\x1b[97m",
};

const LINE = "─".repeat(63);
const DLINE = "═".repeat(63);

export function ln(): void { process.stdout.write("\n"); }
export function out(s: string): void { process.stdout.write(s + "\n"); }

export function separator(): void { out(C.gray + LINE + C.reset); }

export function scenarioHeader(n: number, name: string): void {
  ln();
  out(C.cyan + C.bold + DLINE + C.reset);
  out(C.cyan + C.bold + `  SCENARIO ${n} — ${name}` + C.reset);
  out(C.cyan + C.bold + DLINE + C.reset);
  ln();
}

export function step(n: number, label: string): void {
  out(C.bold + C.white + `[STEP ${n}] ${label}` + C.reset);
}

export function kv(key: string, value: string, indent = "  "): void {
  out(`${indent}${C.gray}${key.padEnd(16)}${C.reset}${value}`);
}

export function check(pass: boolean, label: string, detail: string): void {
  const mark  = pass ? C.green + "✓" : C.red + "✗";
  const lbl   = `  ${mark}  ${C.reset}${label.padEnd(18)}`;
  out(`${lbl}${detail}`);
}

export function blocked(code: string, detail: string): void {
  out(`  ${C.red}✗  BLOCKED${C.reset}  ${C.bold}${code}${C.reset}  ${C.gray}${detail}${C.reset}`);
}

export function resultAllow(label: string): void {
  ln();
  out(C.green + C.bold + `  ┌${"─".repeat(61)}┐`);
  out(`  │  RESULT:  ✓ ALLOW  ${label.padEnd(39)}│`);
  out(`  └${"─".repeat(61)}┘` + C.reset);
  ln();
}

export function resultDeny(code: string, detail: string): void {
  ln();
  out(C.red + C.bold + `  ┌${"─".repeat(61)}┐`);
  out(`  │  RESULT:  ✗ DENY   DENY_REASON = ${code.padEnd(24)}│`);
  out(`  │  ${detail.padEnd(59)}│`);
  out(`  └${"─".repeat(61)}┘` + C.reset);
  ln();
}

export function hash16(h: string): string {
  return C.dim + h.slice(0, 16) + "…" + C.reset;
}

export function fmt(v: unknown): string {
  return JSON.stringify(v);
}
