// SPDX-License-Identifier: Apache-2.0

// Receipt verification
export type {
  SiftDecision,
  SiftReceipt,
  VerifyReceiptOptions,
  VerifyReceiptErrorCode,
  VerifyReceiptResult,
} from "./verifyReceipt.js";
export { verifyReceipt } from "./verifyReceipt.js";

// Intent normalization
export type {
  OxDeAIIntent,
  NormalizedIntentValue,
  NormalizeIntentInput,
  NormalizeIntentErrorCode,
  NormalizeIntentResult,
} from "./normalizeIntent.js";
export { normalizeIntent } from "./normalizeIntent.js";

// State normalization
export type {
  NormalizedStateValue,
  NormalizedState,
  NormalizeStateInput,
  NormalizeStateErrorCode,
  NormalizeStateResult,
} from "./state.js";
export { normalizeState } from "./state.js";

// Authorization construction
export type {
  AuthorizationV1Payload,
  SigningPayload,
  ReceiptToAuthorizationInput,
  ReceiptToAuthorizationErrorCode,
  ReceiptToAuthorizationResult,
} from "./receiptToAuthorization.js";
export { receiptToAuthorization } from "./receiptToAuthorization.js";
