#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI — Hero demo (single adapter: openclaw)
# Used to generate docs/media/oxdeai-demo.gif
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

# Force terminal dimensions so the full output fits
stty cols 110 rows 55

cd ~/OxDeAI-core
clear
sleep 1

echo -n "$ "
echo "pnpm -C examples/openclaw start" | pv -qL 22
sleep 0.3
pnpm -C examples/openclaw start

sleep 4