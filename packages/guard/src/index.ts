/**
 * @oxdeai/guard — Universal Execution Guard for OxDeAI.
 *
 * This package is the single Policy Enforcement Point (PEP) layer for the
 * OxDeAI ecosystem. Runtime adapters (LangGraph, CrewAI, OpenAI, etc.) should
 * delegate all authorization decisions here rather than reimplementing PEP
 * logic themselves.
 */

export { OxDeAIGuard } from "./guard.js";
export { defaultNormalizeAction } from "./normalizeAction.js";
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
} from "./errors.js";
export type { ProposedAction, OxDeAIGuardConfig, GuardDecisionRecord } from "./types.js";
