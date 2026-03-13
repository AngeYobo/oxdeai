#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI — Cross-Adapter Demo Scenario
# Enregistrement asciinema automatique
#
# Usage:
#   asciinema rec --overwrite \
#     --title "OxDeAI — Cross-Adapter Authorization Boundary Demo" \
#     -c "bash scripts/demo-cross-adapter.sh" \
#     docs/media/oxdeai-demo-cross-adapter.cast
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

cd ~/OxDeAI-core
clear

# Simule frappe humaine
type_cmd() {
  echo -n "$ "
  echo "$1" | pv -qL 22
  sleep 0.3
  eval "$1"
}

pause() { sleep "${1:-1.5}"; }

# ── Intro ─────────────────────────────────────────────────────────
pause 1

# ── Step 1: validate all adapters ────────────────────────────────
type_cmd "pnpm validate:adapters"
pause 3

# ── Step 2: run each adapter — même scénario, même résultat ──────
for adapter in openai-tools langgraph crewai openai-agents-sdk autogen openclaw; do
  pause 1.2
  type_cmd "pnpm -C examples/$adapter start"
  pause 1.5
done

pause 3