# Non-bypassable execution boundary demo  ·  v2
#
# What this captures:
#   Scene 1  DENY   - agent proposes drop_table → gateway blocks (destructive op)
#   Scene 2  ALLOW  - agent proposes query_logs → gateway allows → upstream executes
#   Scene 3  BYPASS - agent attempts direct upstream call → connection refused
#
# Output: docs/media/non-bypassable-split-v2.gif
#
# Prerequisites:
#   brew install vhs                                  (macOS)
#   go install github.com/charmbracelet/vhs@latest    (any)
#   apt install vhs                                   (Debian/Ubuntu via charmbracelet PPA)
#
# Run (from repo root):
#   vhs docs/media/non-bypassable-split-v2.tape

Output docs/media/non-bypassable-split-v2.gif

Set Shell       "bash"
Set FontSize    18
Set Width       1100
Set Height      720
Set Theme       "Dracula"
Set Padding     20
Set Framerate   30
Set TypingSpeed 40ms

Hide
Type "clear"
Enter
Show

Type "bash scripts/run-nb-split-demo.sh"
Enter

# title + diagram + 3 scenes + closing ≈ 14s
Sleep 15s
