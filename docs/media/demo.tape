# OxDeAI - Execution Boundary Demo (terminal recording)
#
# Generates docs/demo.gif - embed in README or share directly.
#
# Prerequisites:
#   brew install vhs          (macOS)
#   go install github.com/charmbracelet/vhs@latest  (any)
#   apt install vhs           (Ubuntu/Debian via charmbracelet PPA)
#
# Run:
#   vhs docs/demo.tape

Output docs/demo.gif

Set Shell      "bash"
Set FontSize   20
Set Width      1400
Set Height     720
Set Theme      "Dracula"
Set Padding    10
Set TypingSpeed 30ms

# Build silently, then launch terminal demo
Hide
Type "pnpm -C examples/execution-boundary-demo build 2>/dev/null"
Enter
Sleep 6s
Show

Type "pnpm -C examples/execution-boundary-demo terminal"
Enter

# One full loop:
#   7 frames × 1000ms + 3500ms pause = ~10.5s
# Record 14s to land mid-second-loop (shows it really loops)
Sleep 14s

Ctrl+C
