#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$ROOT"
TMP_DIR="${TMPDIR:-/tmp}/oxdeai-demo-frames"
rm -rf "$TMP_DIR"; mkdir -p "$TMP_DIR" "$OUT_DIR"

FONT="DejaVu-Sans-Mono"
FONT_BOLD="DejaVu-Sans-Mono-Bold"
WIDTH=1100; HEIGHT=720

BG='#0d1117'; BAR='#161b22'; TEXT='#c9d1d9'; DIM='#6e7681'
GREEN='#3fb950'; RED='#f85149'; CYAN='#58a6ff'
YELLOW='#d29922'; PURPLE='#bc8cff'; WHITE='#f0f6fc'

ARGS=()
emit() {
  local src="$1" delay="$2"
  local idx="${#ARGS[@]}"
  local dest; dest="$(printf '%s/frame%04d.png' "$TMP_DIR" "$idx")"
  cp "$src" "$dest"
  ARGS+=( -delay "$delay" -dispose Background "$dest" )
}

make_base() {
  convert -size "${WIDTH}x${HEIGHT}" xc:"$BG" \
    -fill "$BAR"    -draw "rectangle 0,0 ${WIDTH},52" \
    -fill '#ff5f57' -draw "circle 20,26 20,20" \
    -fill '#febc2e' -draw "circle 44,26 44,20" \
    -fill '#28c840' -draw "circle 68,26 68,20" \
    -fill "$DIM" -font "$FONT" -pointsize 14 \
    -gravity North -annotate +0+18 "ange@yobo: ~/OxDeAI-core" \
    -fill '#21262d' -draw "rectangle 0,52 ${WIDTH},54" \
    "$1"
}

# prompt: in out y cmd
# x=248 = tight spacing right after the $ sign
P() {
  convert "$1" \
    -fill "$CYAN"  -font "$FONT_BOLD" -pointsize 15 -annotate +20+"$3"  "ange@yobo:~/OxDeAI-core\$" \
    -fill "$WHITE" -font "$FONT"      -pointsize 15 -annotate +248+"$3" "$4" \
    "$2"
}

LL() { convert "$1" -fill "$4" -font "$FONT"      -pointsize "$5" -annotate +20+"$3" "$6" "$2"; }
LB() { convert "$1" -fill "$4" -font "$FONT_BOLD" -pointsize "$5" -annotate +20+"$3" "$6" "$2"; }

make_base "$TMP_DIR/base.png"

# ── cursor blink ───────────────────────────────────────────────────
P "$TMP_DIR/base.png" "$TMP_DIR/p_empty.png" 95 ""
convert "$TMP_DIR/p_empty.png" -fill "$GREEN" -draw "rectangle 246,81 257,98" "$TMP_DIR/cursor.png"
for i in 1 2 3; do
  emit "$TMP_DIR/cursor.png"  60
  emit "$TMP_DIR/p_empty.png" 60
done
emit "$TMP_DIR/cursor.png" 120

# ═══════════════════════════════════════════════
# SCENE 1 — validate: each adapter PASS
# ═══════════════════════════════════════════════
P "$TMP_DIR/base.png" "$TMP_DIR/s1cmd.png" 95 "pnpm validate:adapters"
emit "$TMP_DIR/s1cmd.png" 350

LL "$TMP_DIR/s1cmd.png" "$TMP_DIR/s1a.png" 126 "$DIM" 13 "> oxdeai-core@ validate:adapters"
LL "$TMP_DIR/s1a.png"   "$TMP_DIR/s1b.png" 144 "$DIM" 13 "> node scripts/validate-adapters.mjs"
emit "$TMP_DIR/s1b.png" 300

declare -a ADAPTERS=(
  "openai-tools........ "
  "langgraph........... "
  "crewai.............. "
  "openai-agents-sdk... "
  "autogen............. "
  "openclaw............ "
)

Y=164; BASE="$TMP_DIR/s1b.png"
for adapter in "${ADAPTERS[@]}"; do
  NEXT="$TMP_DIR/s1v_${Y}.png"
  convert "$BASE" \
    -fill "$TEXT"  -font "$FONT"      -pointsize 15 -annotate +20+"$Y"  "$adapter" \
    -fill "$GREEN" -font "$FONT_BOLD" -pointsize 15 -annotate +272+"$Y" "PASS" \
    "$NEXT"
  emit "$NEXT" 300
  BASE="$NEXT"; Y=$((Y+22))
done
emit "$BASE" 700

# ═══════════════════════════════════════════════
# SCENE 2 — pnpm start: header box
# ═══════════════════════════════════════════════
P "$TMP_DIR/base.png" "$TMP_DIR/s2cmd.png" 95 "pnpm -C examples/openai-tools start"
LL "$TMP_DIR/s2cmd.png" "$TMP_DIR/s2a.png" 126 "$DIM" 13 "> pnpm build && node dist/run.js"
emit "$TMP_DIR/s2a.png" 250

convert "$TMP_DIR/s2a.png" \
  -fill '#1c2128' -draw "rectangle 18,140 1082,198" \
  -fill "$CYAN"   -draw "rectangle 18,140 1082,141" \
  -fill "$CYAN"   -draw "rectangle 18,197 1082,198" \
  -fill "$CYAN"   -draw "rectangle 18,140 19,198" \
  -fill "$CYAN"   -draw "rectangle 1081,140 1082,198" \
  -fill "$WHITE"  -font "$FONT_BOLD" -pointsize 14 -annotate +28+160 "OxDeAI — Pre-Execution Economic Boundary Demo" \
  -fill "$DIM"    -font "$FONT"      -pointsize 13 -annotate +28+180 "Scenario: GPU provisioning — budget for exactly 2 calls" \
  "$TMP_DIR/s2hdr.png"
emit "$TMP_DIR/s2hdr.png" 500

LL "$TMP_DIR/s2hdr.png" "$TMP_DIR/s2i1.png" 218 "$DIM" 13 "Agent:   gpu-agent-1"
LL "$TMP_DIR/s2i1.png"  "$TMP_DIR/s2i2.png" 236 "$DIM" 13 "Policy:  budget=1000 minor units  max_per_action=500  (2x a100 allowed)"
emit "$TMP_DIR/s2i2.png" 450

LB "$TMP_DIR/s2i2.png" "$TMP_DIR/s2sep.png" 262 "$DIM" 13 "── Agent proposals ─────────────────────────────────────────────────"
emit "$TMP_DIR/s2sep.png" 250

# ═══════════════════════════════════════════════
# SCENE 3 — Proposal 1: ALLOW + EXECUTED
# ═══════════════════════════════════════════════
convert "$TMP_DIR/s2sep.png" \
  -fill '#0d1f0d' -draw "rectangle 18,272 1082,370" \
  -fill "$GREEN"  -draw "rectangle 18,272 19,370" \
  -fill "$DIM"    -font "$FONT"      -pointsize 13 -annotate +28+291 "┌─ Proposed tool call" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 13 -annotate +28+309 "│  provision_gpu(asset=a100, region=us-east-1)" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +28+325 "│  cost=500 minor units  nonce=1  intent_id=intent-gpu-1" \
  "$TMP_DIR/s3p1a.png"
emit "$TMP_DIR/s3p1a.png" 300

convert "$TMP_DIR/s3p1a.png" \
  -fill "$GREEN"  -font "$FONT_BOLD" -pointsize 13 -annotate +28+343 "│  ALLOW" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +90+343 "  auth_id=01ca2948f7fcc38d..." \
  "$TMP_DIR/s3p1b.png"
emit "$TMP_DIR/s3p1b.png" 300

convert "$TMP_DIR/s3p1b.png" \
  -fill "$GREEN"  -font "$FONT_BOLD" -pointsize 13 -annotate +28+360 "└─ EXECUTED" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +112+360 "  instance_id=a100-us-east-1-mmo0d8ig" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +28+377 "   budget after: 500/1000 minor units spent" \
  "$TMP_DIR/s3p1c.png"
emit "$TMP_DIR/s3p1c.png" 550

# ═══════════════════════════════════════════════
# SCENE 4 — Proposal 2: ALLOW + EXECUTED
# ═══════════════════════════════════════════════
convert "$TMP_DIR/s3p1c.png" \
  -fill '#0d1f0d' -draw "rectangle 18,387 1082,485" \
  -fill "$GREEN"  -draw "rectangle 18,387 19,485" \
  -fill "$DIM"    -font "$FONT"      -pointsize 13 -annotate +28+406 "┌─ Proposed tool call" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 13 -annotate +28+423 "│  provision_gpu(asset=a100, region=us-east-1)" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +28+439 "│  cost=500 minor units  nonce=2  intent_id=intent-gpu-2" \
  "$TMP_DIR/s4p2a.png"
emit "$TMP_DIR/s4p2a.png" 300

convert "$TMP_DIR/s4p2a.png" \
  -fill "$GREEN"  -font "$FONT_BOLD" -pointsize 13 -annotate +28+457 "│  ALLOW" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +90+457 "  auth_id=c6dea3a8e0d74794..." \
  "$TMP_DIR/s4p2b.png"
emit "$TMP_DIR/s4p2b.png" 300

convert "$TMP_DIR/s4p2b.png" \
  -fill "$GREEN"  -font "$FONT_BOLD" -pointsize 13 -annotate +28+474 "└─ EXECUTED" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +112+474 "  instance_id=a100-us-east-1-mmo0d8ih" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +28+491 "   budget after: 1000/1000 minor units spent" \
  "$TMP_DIR/s4p2c.png"
emit "$TMP_DIR/s4p2c.png" 550

# ═══════════════════════════════════════════════
# SCENE 5 — Proposal 3: DENY
# ═══════════════════════════════════════════════
convert "$TMP_DIR/s4p2c.png" \
  -fill '#1f0d0d' -draw "rectangle 18,501 1082,570" \
  -fill "$RED"    -draw "rectangle 18,501 19,570" \
  -fill "$DIM"    -font "$FONT"      -pointsize 13 -annotate +28+520 "┌─ Proposed tool call" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 13 -annotate +28+537 "│  provision_gpu(asset=a100, region=us-east-1)" \
  -fill "$DIM"    -font "$FONT"      -pointsize 12 -annotate +28+553 "│  cost=500 minor units  nonce=3  intent_id=intent-gpu-3" \
  "$TMP_DIR/s5p3a.png"
emit "$TMP_DIR/s5p3a.png" 300

convert "$TMP_DIR/s5p3a.png" \
  -fill "$RED"    -font "$FONT_BOLD" -pointsize 13 -annotate +28+570 "└─ DENY" \
  -fill "$YELLOW" -font "$FONT"      -pointsize 13 -annotate +90+570 "  reasons: BUDGET_EXCEEDED" \
  "$TMP_DIR/s5p3b.png"
emit "$TMP_DIR/s5p3b.png" 800

# ═══════════════════════════════════════════════
# SCENE 6 — summary + audit + envelope
# ═══════════════════════════════════════════════
make_base "$TMP_DIR/s6base.png"
P "$TMP_DIR/s6base.png" "$TMP_DIR/s6cmd.png" 72 "pnpm -C examples/openai-tools start"

LB "$TMP_DIR/s6cmd.png" "$TMP_DIR/s6s1.png" 102 "$DIM" 13 "── Summary ──────────────────────────────────────────────────────────"
convert "$TMP_DIR/s6s1.png" \
  -fill "$TEXT"  -font "$FONT"      -pointsize 13 -annotate +20+120 "   Allowed:" \
  -fill "$GREEN" -font "$FONT_BOLD" -pointsize 13 -annotate +106+120 "2" \
  -fill "$TEXT"  -font "$FONT"      -pointsize 13 -annotate +126+120 "  Denied:" \
  -fill "$RED"   -font "$FONT_BOLD" -pointsize 13 -annotate +202+120 "1" \
  "$TMP_DIR/s6sum.png"
emit "$TMP_DIR/s6sum.png" 550

LB "$TMP_DIR/s6sum.png" "$TMP_DIR/s6ah.png" 148 "$DIM" 13 "── Audit events (8) ────────────────────────────────────────────"
convert "$TMP_DIR/s6ah.png" \
  -fill "$DIM"   -font "$FONT" -pointsize 12 -annotate +20+165 "   [1773352627] INTENT_RECEIVED  intent=e1389cb6..." \
  -fill "$GREEN" -font "$FONT" -pointsize 12 -annotate +20+180 "   [1773352627] DECISION  decision=ALLOW" \
  -fill "$DIM"   -font "$FONT" -pointsize 12 -annotate +20+195 "   [1773352627] AUTH_EMITTED  intent=e1389cb6..." \
  -fill "$GREEN" -font "$FONT" -pointsize 12 -annotate +20+210 "   [1773352628] DECISION  decision=ALLOW" \
  -fill "$DIM"   -font "$FONT" -pointsize 12 -annotate +20+225 "   [1773352628] AUTH_EMITTED  intent=750c2b7c..." \
  -fill "$RED"   -font "$FONT" -pointsize 12 -annotate +20+240 "   [1773352629] DECISION  decision=DENY" \
  "$TMP_DIR/s6audit.png"
emit "$TMP_DIR/s6audit.png" 550

LB "$TMP_DIR/s6audit.png" "$TMP_DIR/s6eh.png" 265 "$DIM" 13 "── verifyEnvelope (strict mode) ─────────────────────────────────────"
convert "$TMP_DIR/s6eh.png" \
  -fill "$DIM"   -font "$FONT"      -pointsize 12 -annotate +20+283 "   status:" \
  -fill "$GREEN" -font "$FONT_BOLD" -pointsize 12 -annotate +94+283  "ok" \
  -fill "$DIM"   -font "$FONT"      -pointsize 12 -annotate +20+298 "   stateHash:     a849437965c05e101da0c59f..." \
  -fill "$DIM"   -font "$FONT"      -pointsize 12 -annotate +20+313 "   auditHeadHash: 5090d39f4c19ebdc40778c7d..." \
  -fill "$GREEN" -font "$FONT_BOLD" -pointsize 12 -annotate +20+328 "   violations:    none" \
  "$TMP_DIR/s6env.png"
emit "$TMP_DIR/s6env.png" 550

convert "$TMP_DIR/s6env.png" \
  -fill "$GREEN" -font "$FONT_BOLD" -pointsize 14 -annotate +20+354 "✓ Verification passed." \
  "$TMP_DIR/s6ok.png"
emit "$TMP_DIR/s6ok.png" 500

# ═══════════════════════════════════════════════
# SCENE 7 — "What just happened"
# ═══════════════════════════════════════════════
convert "$TMP_DIR/s6ok.png" \
  -fill '#13111f' -draw "rectangle 18,368 1082,558" \
  -fill "$PURPLE" -draw "rectangle 18,368 20,558" \
  -fill '#2a2040' -draw "rectangle 18,368 1082,369" \
  -fill '#2a2040' -draw "rectangle 18,557 1082,558" \
  -fill "$WHITE"  -font "$FONT_BOLD" -pointsize 13 -annotate +28+388 "What just happened:" \
  -fill "$CYAN"   -font "$FONT_BOLD" -pointsize 12 -annotate +28+410 "  PDP" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +75+410 "  OxDeAI evaluated each intent before any tool ran." \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +75+425 "  Call 3 was denied at the boundary — tool never touched." \
  -fill "$CYAN"   -font "$FONT_BOLD" -pointsize 12 -annotate +28+447 "  PEP" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +75+447 "  Tool only executed after Authorization was confirmed." \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +75+462 "  No Authorization = no execution, even on ALLOW." \
  -fill "$CYAN"   -font "$FONT_BOLD" -pointsize 12 -annotate +28+482 "  AUDIT" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +90+482 "  8 hash-chained events record the full execution history." \
  -fill "$CYAN"   -font "$FONT_BOLD" -pointsize 12 -annotate +28+502 "  ENVELOPE" \
  -fill "$TEXT"   -font "$FONT"      -pointsize 12 -annotate +114+502 "  Independently verifiable without re-running the engine." \
  "$TMP_DIR/s7box.png"
emit "$TMP_DIR/s7box.png"  800
emit "$TMP_DIR/s7box.png" 2000   # pause finale

# ── assemble ──────────────────────────────────────────────────────
convert -loop 0 "${ARGS[@]}" "$OUT_DIR/oxdeai-demo.gif"
echo "Done: $OUT_DIR/oxdeai-demo.gif  ($((${#ARGS[@]} / 3)) frames)"