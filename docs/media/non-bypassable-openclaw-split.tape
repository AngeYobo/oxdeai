# Non-bypassable execution boundary demo (OpenClaw agent)
# Output: docs/media/non-bypassable-openclaw-split.gif

Set Shell       "bash"
Set FontSize    18
Set Width       1100
Set Height      720
Set Theme       "Dracula"
Set Padding     20
Set Framerate   30
Set TypingSpeed 40ms

Hide
Type "tmux kill-session -t nbdemo 2>/dev/null || true"
Enter
Type "fuser -k 8787/tcp 8788/tcp 2>/dev/null || true"
Enter
Type "bash scripts/run-nb-openclaw-split-demo.sh"
Enter
Show

Sleep 2000ms
Type "tmux attach -t nbdemo"
Enter

# Allow + deny + replay + bypass fit in ~16s once attached
Sleep 16000ms

Type "tmux kill-session -t nbdemo"
Enter
Sleep 1000ms
