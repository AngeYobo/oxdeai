// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";

/**
 * Protocol-canonical audit hash chain genesis seed.
 *
 * Defined as SHA256("OxDeAI::GENESIS::v1") in lowercase hex.
 * Conformance vector: packages/conformance/vectors/audit-chain.json audit-chain-001
 *   input:  "OxDeAI::GENESIS::v1"
 *   output: "db393af6a9cf189c2b250a0a7dea0c776a3d446c9f51999426f933c53416238b"
 *
 * All audit hash chains MUST start from this value.
 */
export const AUDIT_GENESIS_HASH: string = createHash("sha256")
  .update("OxDeAI::GENESIS::v1", "utf8")
  .digest("hex");
