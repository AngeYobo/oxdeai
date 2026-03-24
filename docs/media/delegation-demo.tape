# OxDeAI — Delegation Demo (terminal recording)
#
# What this captures:
#   Agent A gets real engine authorization (100 units)
#   Agent A delegates narrowed scope to Agent B: max 30 units, tool=provision_gpu
#   Agent B action 1: 20 units → ALLOW  (within delegation scope)
#   Agent B action 2: 50 units → DENY   (exceeds delegation max_amount)
#   auto-loops — shows second pass starting
#
# Output: docs/media/delegation-demo.gif
#
# Prerequisites:
#   brew install vhs                              (macOS)
#   go install github.com/charmbracelet/vhs@latest  (any)
#   apt install vhs                              (Debian/Ubuntu via charmbracelet PPA)
#
# Run:
#   vhs docs/media/delegation-demo.tape

Output docs/media/delegation-demo.gif

Set Shell       "bash"
Set FontSize    20
Set Width       1400
Set Height      780
Set Theme       "Dracula"
Set Padding     12
Set Framerate   30
Set TypingSpeed 22ms

# ── Build (hidden) ────────────────────────────────────────────────────────────
Hide
Type "pnpm -C examples/delegation-demo build 2>/dev/null"
Enter
Sleep 6s
Show

# ── Visible: launch terminal demo ─────────────────────────────────────────────
Sleep 500ms
Type "pnpm -C examples/delegation-demo terminal"
Enter

# ── Scenario timing ───────────────────────────────────────────────────────────
# 7 steps × 1500ms step delay  = 10.5s
# 8000ms hold on final state   =  8.0s
# total per loop               = ~18.5s
#
# 22s: captures full loop + DENY held + loop 2 starting — proves auto-repeat
Sleep 22s

Ctrl+C
