#!/usr/bin/env bash
set -euo pipefail

curl -s -o - -w "\nHTTP %{http_code}\n" \
  -X POST http://localhost:8788/charge \
  -H 'content-type: application/json' \
  --data '{"amount":"500","currency":"USD","user_id":"user_123"}'