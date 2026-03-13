#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI Demo — enregistrement automatique propre
# Lance les commandes avec des pauses naturelles
# Usage: asciinema rec --overwrite docs/media/oxdeai-demo.cast \
#          -c "bash ~/OxDeAI-core/scripts/demo-replay.sh"
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

# Simule une frappe humaine avec délai
type_cmd() {
  echo -n "$ "
  echo "$1" | pv -qL 22   # 22 chars/sec = vitesse de frappe naturelle
  sleep 0.3
  eval "$1"
}

# Pause entre les sections
pause() { sleep "${1:-1.5}"; }

cd ~/OxDeAI-core
clear

echo ""
pause 1

# ── Validate all adapters ────────────────────────────────────────
type_cmd "pnpm validate:adapters"
pause 2

# ── Run each adapter ─────────────────────────────────────────────
for adapter in openai-tools langgraph crewai openai-agents-sdk autogen openclaw; do
  pause 1.5
  type_cmd "pnpm -C examples/$adapter start"
  pause 2
done

pause 3