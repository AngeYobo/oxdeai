/**
 * @oxdeai/openai-agents - thin OpenAI Agents SDK binding for @oxdeai/guard.
 *
 * This package adapts OpenAI Agents SDK tool calls to the universal OxDeAI guard.
 * It contains no authorization logic - all PEP decisions are delegated to
 * @oxdeai/guard. Keep this package thin.
 */

export { createOpenAIAgentsGuard } from "./adapter.js";
export type { OpenAIAgentsToolCall, OpenAIAgentsGuardConfig, OpenAIAgentsGuardFn } from "./types.js";

// Re-export guard error classes so callers can handle them without a
// separate @oxdeai/guard import.
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "@oxdeai/guard";
