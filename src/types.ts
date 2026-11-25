/**
 * Shared types for costguard-ai.
 *
 * The public contract is intentionally small:
 *   GuardAction  --(CostGuard.check)-->  GuardResult { decision, reason, remediation, findings }
 */

/** The outcome of a pre-flight check. */
export type Decision = "ALLOW" | "WARN" | "BLOCK";

/** How serious a single finding is. `block` findings force a BLOCK decision. */
export type Severity = "info" | "warn" | "block";

/** What kind of operation is about to be executed. */
export type ActionKind =
  | "llm_call"
  | "tool_call"
  | "shell_command"
  | "http_request"
  | "file_operation"
  | "database_query"
  | "custom";

export const ACTION_KINDS: readonly ActionKind[] = [
  "llm_call",
  "tool_call",
  "shell_command",
  "http_request",
  "file_operation",
  "database_query",
  "custom",
];

/** Something that is about to happen and should be inspected first. */
export interface GuardAction {
  /** Groups steps into one budget/step/loop scope. Defaults to "default". */
  sessionId?: string;
  kind: ActionKind;
  /** Tool name, endpoint, command label, etc. Used for loop fingerprints. */
  name?: string;
  /** The prompt, command, URL, SQL, or payload that will be sent/executed. */
  input: string;
  /** Model name, used to look up pricing for `llm_call` actions. */
  model?: string;
  /** Known/planned input tokens. Estimated from `input` length if omitted. */
  inputTokens?: number;
  /** Expected output tokens. Falls back to `defaultExpectedOutputTokens`. */
  outputTokens?: number;
  /** Explicit cost estimate in USD. Overrides token-based estimation. */
  estimatedCostUsd?: number;
  /** Free-form data; never inspected or logged by the core guard. */
  metadata?: Record<string, unknown>;
}

/** One issue found while inspecting an action. */
export interface Finding {
  /** Which detector produced it, e.g. "dangerous-pattern", "pii", "repetition". */
  detector: string;
  /** Stable identifier of the rule, e.g. "rm-rf-root". */
  ruleId: string;
  severity: Severity;
  /** Human-readable explanation of what was found. */
  message: string;
  /** What the caller should do about it. */
  remediation: string;
  /** Masked/truncated excerpt of the offending text, never the full secret. */
  match?: string;
}

/** A point-in-time view of a session's consumption. */
export interface SessionSnapshot {
  sessionId: string;
  steps: number;
  maxSteps: number;
  remainingSteps: number;
  spentUsd: number;
  maxBudgetUsd: number;
  remainingBudgetUsd: number;
  warned: number;
  blocked: number;
}

/** The result of inspecting one action. */
export interface GuardResult {
  decision: Decision;
  /** One or two sentences explaining the decision. */
  reason: string;
  /** Suggested fix. "None required." when the decision is ALLOW. */
  remediation: string;
  findings: Finding[];
  sessionId: string;
  /** Estimated cost of this single action in USD. */
  estimatedCostUsd: number;
  /** Session state *after* this decision was applied. */
  session: SessionSnapshot;
  /** ISO-8601 timestamp. */
  timestamp: string;
}

/** A rule that flags dangerous commands, queries, or prompts. */
export interface PatternRule {
  id: string;
  description?: string;
  /** RegExp, or a string compiled with `flags` (default "i"). Strings keep rules JSON-friendly. */
  pattern: RegExp | string;
  flags?: string;
  severity: Severity;
  message: string;
  remediation: string;
  /** Restrict the rule to specific action kinds. Applies to all kinds if omitted. */
  appliesTo?: ActionKind[];
}

/** A rule that flags secrets or personal data. */
export interface PiiRule {
  id: string;
  /** Human label, e.g. "AWS access key". */
  label: string;
  pattern: RegExp | string;
  flags?: string;
  severity: Severity;
  remediation?: string;
  /** Optional second-stage check, e.g. a Luhn check for card numbers. */
  validate?: (match: string) => boolean;
}

export interface ModelPricing {
  inputPerMillionUsd: number;
  outputPerMillionUsd: number;
}

export interface RepetitionConfig {
  /** How many recent actions to look back over. */
  window: number;
  /** Warn when the same action has occurred this many times (including the current one). */
  warnAfter: number;
  /** Block when the same action has occurred this many times (including the current one). */
  blockAfter: number;
  /** Also detect A,B,A,B,A,B style ping-pong loops (warn only). */
  detectCycles: boolean;
}

/** Emitted after every decision (sync via `onDecision`, async via the enterprise hook). */
export interface DecisionEvent {
  timestamp: string;
  sessionId: string;
  kind: ActionKind;
  name?: string;
  /** Redacted, truncated preview of the input. Secrets are replaced with [REDACTED:rule-id]. */
  inputPreview: string;
  result: GuardResult;
}

/**
 * Extension point for audit logging, central policy, and other team/enterprise needs.
 * See `src/enterprise-hook.ts` for a reference implementation.
 */
export interface EnterpriseHook {
  name: string;
  /** Contribute extra findings (e.g. from an organisation-wide policy). */
  extraFindings?(action: GuardAction, session: SessionSnapshot): Promise<Finding[]> | Finding[];
  /** Called after every decision made through `CostGuard.check()` / `protect()`. */
  afterDecision?(event: DecisionEvent): Promise<void> | void;
}

/** What users pass to `new CostGuard(...)`. Everything is optional. */
export interface GuardOptions {
  /** Maximum number of allowed steps per session. Default 25. */
  maxSteps?: number;
  /** Maximum estimated spend per session in USD. Default 1.00. */
  maxBudgetUsd?: number;
  /** Emit WARN once usage reaches this fraction of a limit. Default 0.8. */
  warnAtRatio?: number;
  /** Cost assumed for actions with no cost information. Default 0. */
  defaultCostPerStepUsd?: number;
  /** Output tokens assumed for LLM calls when not specified. Default 500. */
  defaultExpectedOutputTokens?: number;
  /** Pricing table merged over the (illustrative) defaults. Key "default" is the fallback. */
  pricing?: Record<string, ModelPricing>;
  /** Extra dangerous-pattern rules. A rule with an existing id replaces the built-in one. */
  dangerousPatterns?: PatternRule[];
  /** Extra PII/secret rules. A rule with an existing id replaces the built-in one. */
  piiRules?: PiiRule[];
  /** Ids of built-in rules to turn off. */
  disabledRules?: string[];
  repetition?: Partial<RepetitionConfig>;
  /** Called synchronously after every decision. Errors are swallowed. */
  onDecision?: (event: DecisionEvent) => void;
  enterpriseHook?: EnterpriseHook;
}

/** Fully-resolved configuration used internally. */
export interface ResolvedGuardConfig {
  maxSteps: number;
  maxBudgetUsd: number;
  warnAtRatio: number;
  defaultCostPerStepUsd: number;
  defaultExpectedOutputTokens: number;
  pricing: Record<string, ModelPricing>;
  dangerousPatterns: PatternRule[];
  piiRules: PiiRule[];
  repetition: RepetitionConfig;
  onDecision?: (event: DecisionEvent) => void;
  enterpriseHook?: EnterpriseHook;
}
