#!/usr/bin/env bash
set -euo pipefail

SESSION="nbdemo"
TOKEN="demo-internal-token"

tmux kill-session -t "$SESSION" 2>/dev/null || true
fuser -k 8787/tcp 8788/tcp 2>/dev/null || true

tmux new-session -d -s "$SESSION" -n demo 'bash --noprofile --norc'
tmux split-window -h -t "$SESSION":0 'bash --noprofile --norc'
tmux split-window -h -t "$SESSION":0 'bash --noprofile --norc'
tmux select-layout -t "$SESSION":0 even-horizontal

tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format " #{pane_title} "
tmux set-option -t "$SESSION" status off

tmux select-pane -t "$SESSION":0.0 -T "AGENT"
tmux select-pane -t "$SESSION":0.1 -T "GATEWAY"
tmux select-pane -t "$SESSION":0.2 -T "UPSTREAM"

for pane in 0 1 2; do
  tmux send-keys -t "$SESSION":0.$pane 'export PS1="$ "' C-m
done

tmux send-keys -t "$SESSION":0.2 "export UPSTREAM_EXECUTOR_TOKEN=$TOKEN; bash scripts/run-upstream-pane.sh" C-m
sleep 1.5

tmux send-keys -t "$SESSION":0.1 "export UPSTREAM_EXECUTOR_TOKEN=$TOKEN" C-m
tmux send-keys -t "$SESSION":0.1 "bash scripts/run-gateway-pane.sh" C-m
sleep 2

tmux send-keys -t "$SESSION":0.0 "clear; bash scripts/run-agent-pane.sh" C-m

tmux select-pane -t "$SESSION":0.0