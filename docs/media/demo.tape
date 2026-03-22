# OxDeAI — Execution Boundary Demo (terminal recording)
#
# What this captures:
#   same charge_wallet intent evaluated twice against changing state
#   call 1 → ALLOW  (state consistent, side effect committed)
#   call 2 → DENY   (state_consistent: ✗, tool not invoked)
#   auto-loops — shows second pass starting
#
# Output: docs/media/demo.gif
#
# Prerequisites:
#   brew install vhs                              (macOS)
#   go install github.com/charmbracelet/vhs@latest  (any)
#   apt install vhs                              (Debian/Ubuntu via charmbracelet PPA)
#
# Run:
#   vhs docs/media/demo.tape

Output docs/media/demo.gif

Set Shell       "bash"
Set FontSize    20
Set Width       1400
Set Height      760
Set Theme       "Dracula"
Set Padding     12
Set Framerate   30
Set TypingSpeed 22ms

# ── Build (hidden) ────────────────────────────────────────────────────────────
Hide
Type "pnpm -C examples/execution-boundary-demo build 2>/dev/null"
Enter
Sleep 5s
Show

# ── Visible: launch terminal demo ─────────────────────────────────────────────
Sleep 500ms
Type "pnpm -C examples/execution-boundary-demo terminal"
Enter

# ── Scenario timing ───────────────────────────────────────────────────────────
# 7 frames × 1000ms step delay  = 7.0s
# 3500ms hold on final state    = 3.5s
# total per loop                = ~10.5s
#
# 16s: captures full loop, holds on DENY + "tool not invoked",
#      shows loop 2 starting — proves it auto-repeats
Sleep 16s

Ctrl+C
