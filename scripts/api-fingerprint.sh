#!/usr/bin/env bash
set -e

FILE="packages/core/dist/index.d.ts"

if [ ! -f "$FILE" ]; then
  echo "Declaration file not found: $FILE"
  exit 1
fi

sha256sum "$FILE" | awk '{print $1}'