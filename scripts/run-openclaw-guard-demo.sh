#!/usr/bin/env bash
set -euo pipefail

export OXDEAI_ENGINE_SECRET=${OXDEAI_ENGINE_SECRET:-test-secret-must-be-at-least-32-chars!!}

pnpm -C examples/openclaw build
node examples/openclaw/dist/run.js
