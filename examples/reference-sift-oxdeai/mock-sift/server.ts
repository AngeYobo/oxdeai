// SPDX-License-Identifier: Apache-2.0
/**
 * Mock Sift server for integration testing.
 *
 * Issues Ed25519-signed receipts with valid receipt_hash and signature,
 * matching the exact wire format that verifyReceipt / verifyReceiptWithKeyStore
 * expect. Also exposes /sift-jwks.json and /sift-krl.json.
 *
 * NOT for production use. Designed to be started programmatically by tests.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, createPublicKey, sign, randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { siftCanonicalJsonBytes, b64uEncode } from "../shared/canonical.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MockSiftConfig {
  port: number;
  privateKey: KeyObject;
  kid: string;
}

export interface MockSiftHandle {
  url: string;
  close(): Promise<void>;
}

interface ReceiptRequest {
  tool: string;
  decision?: "ALLOW" | "DENY";
  policy?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function rawBytesFromPublicKey(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return der.subarray(12); // strip the 12-byte SPKI prefix, leaving 32 raw bytes
}

/**
 * Builds a complete, signed SiftReceipt.
 *
 * Signing order (must match verifyReceipt exactly):
 *   1. Build receipt body (all fields except signature and receipt_hash)
 *   2. receipt_hash = SHA-256(siftCanonical(body))
 *   3. signed payload = body + receipt_hash
 *   4. signature = Ed25519(siftCanonical(signed_payload)) → base64url
 */
function buildReceipt(
  tool: string,
  decision: "ALLOW" | "DENY",
  policy: string,
  privateKey: KeyObject
): Record<string, unknown> {
  const body = {
    receipt_version: "1.0",
    tenant_id: "tenant-acme",
    agent_id: "agent-001",
    action: "call_tool",
    tool,
    decision,
    risk_tier: 2,
    timestamp: new Date().toISOString(),
    nonce: randomUUID(),
    policy_matched: policy,
  };

  const receiptHash = createHash("sha256")
    .update(siftCanonicalJsonBytes(body))
    .digest("hex");

  const signedPayload = { ...body, receipt_hash: receiptHash };
  const preimage = siftCanonicalJsonBytes(signedPayload);
  const sigBuf = sign(null, preimage, privateKey);

  return { ...signedPayload, signature: b64uEncode(sigBuf) };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

// ─── Server ───────────────────────────────────────────────────────────────────

export function startMockSift(config: MockSiftConfig): Promise<MockSiftHandle> {
  return new Promise((resolve, reject) => {
    const publicKey = createPublicKey(config.privateKey);
    const rawPub = rawBytesFromPublicKey(publicKey);

    const jwks = {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          kid: config.kid,
          x: b64uEncode(rawPub),
        },
      ],
    };

    const krl = { revoked_kids: [] };

    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const url = req.url ?? "/";

        if (url === "/sift-jwks.json" && req.method === "GET") {
          return jsonResponse(res, 200, jwks);
        }

        if (url === "/sift-krl.json" && req.method === "GET") {
          return jsonResponse(res, 200, krl);
        }

        if (url === "/receipt" && req.method === "POST") {
          const rawBody = await readBody(req);
          let parsed: ReceiptRequest;
          try {
            parsed = JSON.parse(rawBody) as ReceiptRequest;
          } catch {
            return jsonResponse(res, 400, { error: "Invalid JSON" });
          }

          if (!parsed.tool || typeof parsed.tool !== "string") {
            return jsonResponse(res, 400, { error: "Missing required field: tool" });
          }

          const decision = parsed.decision === "DENY" ? "DENY" : "ALLOW";
          const policy = parsed.policy ?? "transfer-policy-v1";
          const receipt = buildReceipt(parsed.tool, decision, policy, config.privateKey);

          return jsonResponse(res, 200, { kid: config.kid, receipt });
        }

        return jsonResponse(res, 404, { error: "Not found" });
      } catch (e) {
        return jsonResponse(res, 500, {
          error: e instanceof Error ? e.message : String(e),
        });
      }
    });

    server.on("error", reject);

    server.listen(config.port, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Unexpected server address type"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close(): Promise<void> {
          return new Promise((res, rej) =>
            server.close((e) => (e ? rej(e) : res()))
          );
        },
      });
    });
  });
}
