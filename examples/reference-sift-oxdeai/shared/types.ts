// SPDX-License-Identifier: Apache-2.0
/**
 * Shared types used across the reference implementation.
 * OxDeAI types re-exported from @oxdeai/sift to keep imports DRY.
 */

export type {
  AuthorizationV1Payload,
  SigningPayload,
  OxDeAIIntent,
  NormalizedState,
} from "@oxdeai/sift";

// ─── Mock-Sift delivery envelope ─────────────────────────────────────────────

/**
 * The envelope returned by mock-sift (and real Sift) when issuing a receipt.
 * In production the kid typically comes from the HTTP delivery context;
 * we make it explicit here.
 */
export interface ReceiptEnvelope {
  kid: string;
  receipt: unknown;
}

// ─── PEP Gateway request/response ────────────────────────────────────────────

export interface ExecuteRequest {
  intent: unknown;
  state: unknown;
  authorization: unknown;
}

export interface ExecuteResponse {
  ok: boolean;
  executed?: boolean;
  code?: string;
  message?: string;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

import type { OxDeAIIntent, NormalizedState, AuthorizationV1Payload } from "@oxdeai/sift";

export interface AdapterInput {
  kidAndReceipt: ReceiptEnvelope;
  params: Record<string, unknown>;
  state: Record<string, unknown>;
  /** Override the wall-clock time for receiptToAuthorization. Test-only. */
  now?: Date;
}

export type AdapterSuccess = {
  ok: true;
  authorization: AuthorizationV1Payload;
  intent: OxDeAIIntent;
  state: NormalizedState;
};

export type AdapterFailure = {
  ok: false;
  code: string;
  message: string;
};

export type AdapterResult = AdapterSuccess | AdapterFailure;
