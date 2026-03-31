Output docs/media/openai-demo.gif

Set Shell  "bash"
Set FontSize   13
Set Width     860
Set Height    520
Set Framerate  24
Set PlaybackSpeed 0.75

# ── Type the command visibly ─────────────────────────────────────────────────
Type "pnpm -C examples/openai-tools demo:openai"

# ── Hide during build only (pnpm noise + tsc) ────────────────────────────────
# Build takes ~5–8s. clear runs after. Demo starts streaming at ~8s.
# Show resumes while demo is still live → VHS captures the stream.
Hide
Enter
Sleep 8s
Show

# ── Demo streams from here — sleep is the only pacing control ────────────────
# 25s covers: header + 3 API calls + timeline + verification + summary box.
Sleep 25s
