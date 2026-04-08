#!/usr/bin/env bash
# Demo script for non-bypassable-split-v2.tape
# Runs as a sub-process - VHS types the invocation, this handles the output + timing

# ── Title ─────────────────────────────────────────────────────────────────────

printf '\e[1;36m╔═══════════════════════════════════════════════════════════╗\e[0m\n'
printf '\e[1;36m║  OxDeAI  ·  Non-Bypassable Execution Boundary             ║\e[0m\n'
printf '\e[1;36m║  every proposal intercepted  ·  no direct upstream path   ║\e[0m\n'
printf '\e[1;36m╚═══════════════════════════════════════════════════════════╝\e[0m\n'
sleep 0.9

# ── Flow diagram ──────────────────────────────────────────────────────────────

printf '\n\e[90m  ┌───────────┐        ┌───────────────┐        ┌─────────────┐\e[0m\n'
printf '\e[90m  │   AGENT   │  ───►  │    GATEWAY    │  ───►  │  UPSTREAM   │\e[0m\n'
printf '\e[90m  └───────────┘        └───────────────┘        └─────────────┘\e[0m\n'
printf '\e[90m   proposes calls          intercepts               executes\e[0m\n'
printf '\e[90m                           + evaluates              on ALLOW\e[0m\n'
sleep 1.1

# ── Scene 1 · DENY ────────────────────────────────────────────────────────────

printf '\n\e[90m── scene 1 ──────────────────────────────────────────────────\e[0m\n'
sleep 0.4

printf '  \e[1;36m[AGENT   ]\e[0m  propose › drop_table(table=users)\n'
sleep 0.7

printf '  \e[1;33m[GATEWAY ]\e[0m  received · evaluating policy...\n'
sleep 0.8

printf '  \e[1;33m[GATEWAY ]\e[0m  \e[1;31m✗ DENY\e[0m   destructive op on protected table\n'
sleep 0.5

printf '  \e[1;35m[UPSTREAM]\e[0m  \e[90m- not reached\e[0m\n'
sleep 1.0

# ── Scene 2 · ALLOW ───────────────────────────────────────────────────────────

printf '\n\e[90m── scene 2 ──────────────────────────────────────────────────\e[0m\n'
sleep 0.4

printf '  \e[1;36m[AGENT   ]\e[0m  propose › query_logs(window=last_24h)\n'
sleep 0.7

printf '  \e[1;33m[GATEWAY ]\e[0m  received · evaluating policy...\n'
sleep 0.8

printf '  \e[1;33m[GATEWAY ]\e[0m  \e[1;32m✓ ALLOW\e[0m  read-only · within scope\n'
sleep 0.5

printf '  \e[1;35m[UPSTREAM]\e[0m  query_logs() \e[1;32m→ 200 OK\e[0m  (47 entries returned)\n'
sleep 1.0

# ── Scene 3 · Bypass attempt ──────────────────────────────────────────────────

printf '\n\e[90m── scene 3 · bypass attempt ─────────────────────────────────\e[0m\n'
sleep 0.4

printf '  \e[1;36m[AGENT   ]\e[0m  \e[90m(attempts direct connection to upstream :8788)\e[0m\n'
sleep 0.8

printf '  \e[1;31m[AGENT   ]\e[0m  \e[31mconnection refused - no direct route exists\e[0m\n'
sleep 0.5

printf '  \e[1;35m[UPSTREAM]\e[0m  \e[90m- not reached\e[0m\n'
sleep 1.0

# ── Closing ───────────────────────────────────────────────────────────────────

printf '\n\e[1;37mThe boundary is structural.  The agent cannot bypass it.  Ever.\e[0m\n'
sleep 1.8
