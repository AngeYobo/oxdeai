# Non-bypassable execution boundary demo (split-screen)
# Output: docs/media/non-bypassable-split.gif

Set Shell "bash"
Set FontSize 20
Set Width 1400
Set Height 760
Set Theme "Dracula"
Set Padding 12
Set Framerate 30
Set TypingSpeed 60ms

Hide

Type "tmux kill-session -t nbdemo 2>/dev/null || true"
Enter
Sleep 600ms
Type "fuser -k 8787/tcp 8788/tcp 2>/dev/null || true"
Enter
Sleep 600ms
Type "bash scripts/start-non-bypassable-tmux.sh"
Enter

Sleep 3500ms

Show
Type "tmux attach -t nbdemo"
Enter

Sleep 28000ms

Type "tmux kill-session -t nbdemo"
Enter
Sleep 1800ms
