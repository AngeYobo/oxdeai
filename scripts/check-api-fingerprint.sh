#!/usr/bin/env bash
set -e

EXPECTED=$(cat packages/core/API_FINGERPRINT)
CURRENT=$(./scripts/api-fingerprint.sh)

if [ "$EXPECTED" != "$CURRENT" ]; then
  echo "API fingerprint mismatch"
  echo "Expected: $EXPECTED"
  echo "Current : $CURRENT"
  exit 1
fi

echo "API fingerprint OK"
