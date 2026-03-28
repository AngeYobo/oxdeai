# OxDeAI × Agentgram — Live Sandbox Demo (terminal recording)
#
# What this captures:
#   Phase A  Bootstrap         — register_agent (or skip if key present)
#   Phase B  Discovery         — read_home · read_feed · fetch_memory
#   Phase C  Interaction       — like_post (ALLOW) · comment_post (ALLOW)
#   Phase D  Replay protection — read_home nonce 999 (ALLOW first) → DENY replay
#   Phase E  Invalid target    — like_post invalid-post-id → DENY allowlist
#
# Output: docs/media/agentgram-demo.gif
#
# Prerequisites:
#   brew install vhs                                (macOS)
#   go install github.com/charmbracelet/vhs@latest  (any)
#   apt install vhs                                 (Debian/Ubuntu via charmbracelet PPA)
#
# Required env vars (set before running vhs):
#   export AGENTGRAM_AGENT_NAME=<your-agent-name>
#   export AGENTGRAM_TARGET_AGENT_NAME=<target-agent-name>
#   export AGENTGRAM_API_KEY=<your-api-key>          # optional — bootstrap registers if absent
#   export AGENTGRAM_TARGET_POST_ID=<post-id>        # optional — auto-discovered from /feed
#   export OXDEAI_ENGINE_SECRET=<secret>             # optional — demo secret used if absent
#
# Run:
#   vhs docs/media/agentgram-demo.tape

Output docs/media/agentgram-demo.gif

Set Shell       "bash"
Set FontSize    20
Set Width       1400
Set Height      820
Set Theme       "Dracula"
Set Padding     12
Set Framerate   30
Set TypingSpeed 22ms

# ── Build (hidden) ────────────────────────────────────────────────────────────
Hide
Type "pnpm install --frozen-lockfile 2>/dev/null && pnpm -C examples/agentgram-demo typecheck 2>/dev/null"
Enter
Sleep 10s
Show

# ── Visible: launch live demo ─────────────────────────────────────────────────
Sleep 500ms
Type "pnpm -C examples/agentgram-demo live"
Enter

# ── Timing breakdown ──────────────────────────────────────────────────────────
# Phase A  bootstrap/skip      ~0.5s
# Phase B  3 HTTP calls        ~1.5s  (read_home, read_feed, fetch_memory)
# Phase C  2 HTTP calls        ~1.0s  (like_post, comment_post)
# Phase D  2 calls + DENY      ~0.5s
# Phase E  1 DENY              ~0.2s
# Terminal render + padding    ~1.5s
# Hold on final state          ~6.0s  (viewer reads ALLOW/DENY rows)
# Total                       ~11.5s  → budget 14s

Sleep 10s

# ── Hold on final state ───────────────────────────────────────────────────────
Sleep 6s
