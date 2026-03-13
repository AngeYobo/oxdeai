#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OxDeAI Demo — pipeline complet record → render → optimize
# Usage: bash scripts/make-demo.sh
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MEDIA="$ROOT/docs/media"
CAST="$MEDIA/oxdeai-demo.cast"
GIF="$MEDIA/oxdeai-demo.gif"
GIF_OPT="$MEDIA/oxdeai-demo-opt.gif"

mkdir -p "$MEDIA"

# ── 1. RECORD ────────────────────────────────────────────────────
# Deux modes : auto (via demo-replay.sh) ou manuel
if [[ "${1:-}" == "--auto" ]]; then
  echo "▶  Enregistrement automatique..."

  # pv requis pour la simulation de frappe: sudo apt install pv
  asciinema rec \
    --overwrite \
    --title "OxDeAI — deterministic authorization boundary for agent actions" \
    -c "bash $ROOT/scripts/demo-replay.sh" \
    "$CAST"
else
  echo ""
  echo "▶  Enregistrement manuel"
  echo "   Lance ces commandes dans l'ordre dans le shell qui va s'ouvrir :"
  echo ""
  echo "   pnpm validate:adapters"
  echo ""
  echo "   pnpm -C examples/openai-tools start"
  echo "   pnpm -C examples/langgraph start"
  echo "   pnpm -C examples/crewai start"
  echo "   pnpm -C examples/openai-agents-sdk start"
  echo "   pnpm -C examples/autogen start"
  echo "   pnpm -C examples/openclaw start"
  echo ""
  echo "   Puis: exit"
  echo ""
  read -rp "   ENTER pour démarrer..."

  asciinema rec \
    --overwrite \
    --title "OxDeAI — deterministic authorization boundary for agent actions" \
    -c "bash --login" \
    "$CAST"
fi

echo ""
echo "✓  Cast enregistré: $CAST"

# ── 2. RENDER avec agg ───────────────────────────────────────────
echo "   Rendu GIF..."

agg \
  --font-size 14 \
  --font-family "JetBrains Mono,Fira Code,Cascadia Code,DejaVu Sans Mono" \
  --theme "$(cat << 'THEME'
{
  "foreground": "#c9d1d9",
  "background": "#0d1117",
  "palette": [
    "#484f58", "#f85149", "#3fb950", "#d29922",
    "#58a6ff", "#bc8cff", "#58a6ff", "#c9d1d9",
    "#6e7681", "#f85149", "#3fb950", "#d29922",
    "#58a6ff", "#bc8cff", "#58a6ff", "#f0f6fc"
  ]
}
THEME
)" \
  --speed 1.0 \
  --last-frame-duration 5 \
  --idle-time-limit 1.5 \
  "$CAST" \
  "$GIF"

echo "✓  GIF rendu: $GIF"

# ── 3. OPTIMIZE avec gifsicle ────────────────────────────────────
if command -v gifsicle &>/dev/null; then
  echo "   Optimisation gifsicle..."
  gifsicle \
    --optimize=3 \
    --colors 256 \
    --lossy=40 \
    "$GIF" \
    -o "$GIF_OPT"
  
  ORIG=$(du -sh "$GIF"     | cut -f1)
  OPT=$(du -sh  "$GIF_OPT" | cut -f1)
  echo "✓  Optimisé: $ORIG → $OPT"
  echo "   Fichier final: $GIF_OPT"
else
  echo "   (gifsicle non installé — sudo apt install gifsicle)"
  echo "   Fichier final: $GIF"
fi

echo ""
echo "Done."