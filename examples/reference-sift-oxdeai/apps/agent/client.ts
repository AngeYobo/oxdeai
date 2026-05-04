// SPDX-License-Identifier: Apache-2.0
/**
 * Agent HTTP client helpers.
 *
 * The agent coordinates:
 *   1. Fetch a Sift receipt (from mock-sift or real Sift)
 *   2. Call the adapter to get a signed AuthorizationV1
 *   3. Call the PEP Gateway with the intent + state + authorization
 *
 * In the reference implementation the adapter is called as a library
 * (not over HTTP). The PEP Gateway and upstream are HTTP servers.
 */

import type { OxDeAIIntent, NormalizedState, AuthorizationV1Payload } from "@oxdeai/sift";
import type { ReceiptEnvelope } from "../../shared/types.js";

// ─── Mock-Sift ────────────────────────────────────────────────────────────────

/**
 * Requests a signed receipt from mock-sift (or real Sift).
 * Returns the receipt envelope containing { kid, receipt }.
 */
export async function fetchSiftReceipt(
  siftUrl: string,
  tool: string,
  decision: "ALLOW" | "DENY" = "ALLOW",
  policy?: string
): Promise<ReceiptEnvelope> {
  const res = await fetch(`${siftUrl}/receipt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, decision, policy }),
  });
  if (!res.ok) {
    throw new Error(`Mock-sift /receipt returned HTTP ${res.status}`);
  }
  return res.json() as Promise<ReceiptEnvelope>;
}

// ─── PEP Gateway ──────────────────────────────────────────────────────────────

export interface PepResponse {
  status: number;
  body: unknown;
}

/**
 * Submits an execution request to the PEP Gateway.
 * The PEP performs the 9-step AuthorizationV1 verification before forwarding
 * to upstream.
 */
export async function callPepGateway(
  pepUrl: string,
  intent: OxDeAIIntent | unknown,
  state: NormalizedState | unknown,
  authorization: AuthorizationV1Payload | unknown
): Promise<PepResponse> {
  const res = await fetch(`${pepUrl}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ intent, state, authorization }),
  });
  return { status: res.status, body: await res.json() };
}
