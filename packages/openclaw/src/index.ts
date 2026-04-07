// SPDX-License-Identifier: Apache-2.0
/**
 * @oxdeai/openclaw - thin OpenClaw binding for @oxdeai/guard.
 *
 * This package adapts OpenClaw action/skill calls to the universal OxDeAI guard.
 * It contains no authorization logic - all PEP decisions are delegated to
 * @oxdeai/guard. Keep this package thin.
 */

export { createOpenClawGuard } from "./adapter.js";
export type { OpenClawAction, OpenClawGuardConfig, OpenClawGuardFn } from "./types.js";

// Re-export guard error classes so callers can handle them without a
// separate @oxdeai/guard import.
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "@oxdeai/guard";
