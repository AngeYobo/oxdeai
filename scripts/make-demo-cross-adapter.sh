#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI — pipeline cross-adapter demo
# Usage: bash scripts/make-demo-cross-adapter.sh
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MEDIA="$ROOT/docs/media"
CAST="$MEDIA/oxdeai-demo-cross-adapter.cast"
GIF="$MEDIA/oxdeai-demo-cross-adapter.gif"

mkdir -p "$MEDIA"

echo "▶  Enregistrement cross-adapter demo..."
asciinema rec \
  --overwrite \
  --title "OxDeAI — Cross-Adapter Authorization Boundary Demo" \
  -c "bash $ROOT/scripts/demo-cross-adapter.sh" \
  "$CAST"

echo "✓  Cast: $CAST"
echo "   Rendu GIF..."

agg \
  --font-size 14 \
  --theme github-dark \
  --idle-time-limit 1.5 \
  --last-frame-duration 5 \
  "$CAST" \
  "$GIF"

echo "✓  GIF: $GIF"

if command -v gifsicle &>/dev/null; then
  gifsicle --optimize=3 --colors 256 "$GIF" -o "$GIF"
  echo "✓  Optimisé: $(du -sh "$GIF" | cut -f1)"
fi

explorer.exe "$MEDIA/" 2>/dev/null || true
echo "Done."