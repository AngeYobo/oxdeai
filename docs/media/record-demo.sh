#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI Demo — asciinema record + agg render
# Usage:  bash scripts/record-demo.sh
# Output: docs/media/oxdeai-demo.gif
#
# Requires:
#   asciinema  → pip install asciinema
#   agg        → cargo install agg   OR   brew install agg
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAST="$ROOT/docs/media/oxdeai-demo.cast"
GIF="$ROOT/docs/media/oxdeai-demo.gif"

mkdir -p "$ROOT/docs/media"

# ── 1. record ─────────────────────────────────────────────────────
echo ""
echo "▶  Recording OxDeAI demo — run your commands, then Ctrl+D to stop"
echo "   Commands to run:"
echo ""
echo "   pnpm validate:adapters"
echo "   pnpm -C examples/openai-tools start"
echo "   pnpm -C examples/langgraph start"
echo "   pnpm -C examples/crewai start"
echo ""
echo "   Press ENTER to start recording..."
read -r

asciinema rec \
  --cols 110 \
  --rows 35 \
  --title "OxDeAI — deterministic authorization boundary for agent actions" \
  --command "bash --login" \
  "$CAST"

echo ""
echo "✓ Saved cast: $CAST"

# ── 2. render ─────────────────────────────────────────────────────
echo "   Rendering GIF..."

agg \
  --font-size 15 \
  --font-family "JetBrains Mono,Fira Code,DejaVu Sans Mono" \
  --theme monokai \
  --cols 110 \
  --rows 35 \
  --speed 1.0 \
  --last-frame-duration 4 \
  "$CAST" \
  "$GIF"

echo "✓ Generated: $GIF"
echo ""
echo "   Preview:  open $GIF"
echo "   Optimize: gifsicle -O3 --colors 256 $GIF -o $GIF"