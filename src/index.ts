/**
 * costguard-ai: pre-execution guardrail for AI apps and agents.
 * Public API surface.
 */

export { CostGuard, GuardBlockedError, resolveConfig } from "./guard.js";
export {
  DEFAULT_DANGEROUS_PATTERNS,
  DEFAULT_PII_RULES,
  DEFAULT_PRICING,
  compilePattern,
  detectDangerous,
  detectPii,
  detectRepetition,
  estimateActionCost,
  estimateTokens,
  fingerprintAction,
  luhnCheck,
  maskValue,
  redactSensitive,
  resolvePricing,
} from "./detectors.js";
export {
  JsonlAuditSink,
  MemoryAuditSink,
  WebhookAuditSink,
  createEnterpriseHook,
} from "./enterprise-hook.js";
export type { AuditRecord, AuditSink, EnterpriseHookOptions } from "./enterprise-hook.js";
export { formatReport, loadScenario, replayScenario, validateScenario } from "./replay.js";
export type {
  ReplayReport,
  ReplayScenario,
  ReplayStep,
  ReplayStepResult,
  ScenarioConfig,
} from "./replay.js";
export { ACTION_KINDS } from "./types.js";
export type {
  ActionKind,
  Decision,
  DecisionEvent,
  EnterpriseHook,
  Finding,
  GuardAction,
  GuardOptions,
  GuardResult,
  ModelPricing,
  PatternRule,
  PiiRule,
  RepetitionConfig,
  ResolvedGuardConfig,
  SessionSnapshot,
  Severity,
} from "./types.js";
