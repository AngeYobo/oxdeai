// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { verifyEnvelope } from "@oxdeai/core";

const path = process.argv[2];
if (!path) {
  console.error("usage: node verify-envelope.js <envelope.bin>");
  process.exit(1);
}

const envelopeBytes = new Uint8Array(readFileSync(path));
// Best-effort mode: structural checks only, no issuer trust required.
// Production PEP code must use strict mode with explicit trustedKeySets:
//   verifyEnvelope(bytes, { mode: "strict", trustedKeySets: [...] })
const result = verifyEnvelope(envelopeBytes);
console.log(JSON.stringify(result, null, 2));
