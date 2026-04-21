#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Legacy entry point intentionally made non-executable for protected actions.
// Use the reusable PEP gateway in examples/non-bypassable-demo/pep-gateway.mjs,
// which delegates to @oxdeai/guard.

console.error(
  [
    "scripts/pep-gateway.mjs has been disabled for ETA conformance.",
    "It is not a protected execution boundary.",
    "Run the verified reusable gateway instead:",
    "  UPSTREAM_EXECUTOR_TOKEN=<token> pnpm -C examples/non-bypassable-demo gateway",
  ].join("\n")
);
process.exit(1);
