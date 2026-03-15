/**
 * @oxdeai/autogen — thin AutoGen binding for @oxdeai/guard.
 *
 * This package adapts AutoGen function/tool calls to the universal OxDeAI guard.
 * It contains no authorization logic — all PEP decisions are delegated to
 * @oxdeai/guard. Keep this package thin.
 */

export { createAutoGenGuard } from "./adapter.js";
export type { AutoGenToolCall, AutoGenGuardConfig, AutoGenGuardFn } from "./types.js";

// Re-export guard error classes so callers can handle them without a
// separate @oxdeai/guard import.
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "@oxdeai/guard";
