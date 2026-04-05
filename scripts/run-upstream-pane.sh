#!/usr/bin/env bash
set -euo pipefail

: "${UPSTREAM_EXECUTOR_TOKEN:?missing UPSTREAM_EXECUTOR_TOKEN}"

clear
# printf "%s\n" "UPSTREAM"


node examples/non-bypassable-demo/protected-upstream.mjs