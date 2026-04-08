# OpenClaw in-process guard demo (OxDeAI)
# Output: docs/media/openclaw-guard-demo.gif

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

Type "bash scripts/run-openclaw-guard-demo.sh"
Enter

# Build + run prints three calls (ALLOW/ALLOW/DENY). Wait for completion.
Sleep 23000ms
