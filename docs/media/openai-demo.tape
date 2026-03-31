Output docs/media/openai-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 860
Set Height 520
Set Framerate 24
Set PlaybackSpeed 0.85

# ── Hook (visible immédiatement) ─────────────────────────────────
Type "# same call ×3"
Enter
Type "#"
Enter
Type "#   ALLOW"
Enter
Type "#   ALLOW"
Enter
Type "#   DENY"
Enter
Type "#"
Enter
Type "# blocked before execution"
Enter
Sleep 1.2s

# ── Command ─────────────────────────────────────────────────────
Type "pnpm -C examples/openai-tools demo:openai"
Enter

# ── Hide build ──────────────────────────────────────────────────
Hide
Sleep 7s
Show

# ── Live decisions (core signal) ─────────────────────────────────
Sleep 12s

# ── Hold on DENY (critical moment) ──────────────────────────────
Sleep 2s

# ── Transition ──────────────────────────────────────────────────
Type "# artifact replay (no engine)"
Enter
Sleep 1.5s

# ── Offline verification ────────────────────────────────────────
Sleep 6s

# ── Final pause ─────────────────────────────────────────────────
Sleep 2s