/**
 * @oxdeai/crewai — thin CrewAI binding for @oxdeai/guard.
 *
 * This package adapts CrewAI tool calls to the universal OxDeAI guard.
 * It contains no authorization logic — all PEP decisions are delegated to
 * @oxdeai/guard. Keep this package thin.
 */

export { createCrewAIGuard } from "./adapter.js";
export type { CrewAIToolCall, CrewAIGuardConfig, CrewAIGuardFn } from "./types.js";

// Re-export guard error classes so callers can handle them without a
// separate @oxdeai/guard import.
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "@oxdeai/guard";
