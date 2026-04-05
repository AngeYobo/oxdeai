#!/usr/bin/env bash
set -euo pipefail

RED="$(printf '\033[31m')"
GREEN="$(printf '\033[32m')"
YELLOW="$(printf '\033[33m')"
NC="$(printf '\033[0m')"

clear
# printf "%sAGENT%s\n" "$GREEN" "$NC"


# 🔴 Direct call
printf "%sDIRECT_CALL_NO_AUTH_EXPECT_403%s\n" "$RED" "$NC"
bash scripts/direct-bypass-test.sh

# 🟡 Separator
printf "\n%s---- AUTHORIZED_PATH ----%s\n\n" "$YELLOW" "$NC"

node examples/non-bypassable-demo/agent.mjs
