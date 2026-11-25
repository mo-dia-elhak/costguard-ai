/**
 * CostGuard: the pre-flight interceptor.
 *
 *   const guard = new CostGuard({ maxSteps: 20, maxBudgetUsd: 0.5 });
 *   const result = guard.evaluate({ kind: "shell_command", input: "rm -rf /" });
 *   // result.decision === "BLOCK"
 */

import {
  DEFAULT_DANGEROUS_PATTERNS,
  DEFAULT_PII_RULES,
  DEFAULT_PRICING,
  detectDangerous,
  detectPii,
  detectRepetition,
  estimateActionCost,
  fingerprintAction,
  redactSensitive,
} from "./detectors.js";
import type {
  Decision,
  DecisionEvent,
  Finding,
  GuardAction,
  GuardOptions,
  GuardResult,
  ResolvedGuardConfig,
  SessionSnapshot,
  Severity,
} from "./types.js";

const DEFAULT_SESSION_ID = "default";
const HISTORY_CAP = 200;
const EPSILON = 1e-12;

interface SessionState {
  steps: number;
  spentUsd: number;
  warned: number;
  blocked: number;
  /** Fingerprints of every attempt (including blocked ones), oldest first. */
  history: string[];
}

/** Thrown by `protect()` when an action is blocked. */
export class GuardBlockedError extends Error {
  readonly result: GuardResult;
  constructor(result: GuardResult) {
    super(`Blocked by costguard-ai: ${result.reason} Fix: ${result.remediation}`);
    this.name = "GuardBlockedError";
    this.result = result;
  }
}

function mergeById<T extends { id: string }>(defaults: T[], custom: T[] | undefined, disabled: Set<string>): T[] {
  const map = new Map<string, T>();
  for (const item of defaults) if (!disabled.has(item.id)) map.set(item.id, item);
  for (const item of custom ?? []) map.set(item.id, item);
  return [...map.values()];
}

/** Merge user options over defaults and validate them. Throws RangeError on nonsense values. */
export function resolveConfig(options: GuardOptions = {}): ResolvedGuardConfig {
  const disabled = new Set(options.disabledRules ?? []);
  const config: ResolvedGuardConfig = {
    maxSteps: options.maxSteps ?? 25,
    maxBudgetUsd: options.maxBudgetUsd ?? 1,
    warnAtRatio: options.warnAtRatio ?? 0.8,
    defaultCostPerStepUsd: options.defaultCostPerStepUsd ?? 0,
    defaultExpectedOutputTokens: options.defaultExpectedOutputTokens ?? 500,
    pricing: { ...DEFAULT_PRICING, ...options.pricing },
    dangerousPatterns: mergeById(DEFAULT_DANGEROUS_PATTERNS, options.dangerousPatterns, disabled),
    piiRules: mergeById(DEFAULT_PII_RULES, options.piiRules, disabled),
    repetition: {
      window: 10,
      warnAfter: 3,
      blockAfter: 5,
      detectCycles: true,
      ...options.repetition,
    },
    ...(options.onDecision ? { onDecision: options.onDecision } : {}),
    ...(options.enterpriseHook ? { enterpriseHook: options.enterpriseHook } : {}),
  };

  if (!(config.maxSteps > 0)) throw new RangeError("maxSteps must be greater than 0");
  if (!(config.maxBudgetUsd >= 0)) throw new RangeError("maxBudgetUsd must be 0 or greater");
  if (!(config.warnAtRatio > 0 && config.warnAtRatio <= 1)) {
    throw new RangeError("warnAtRatio must be in the range (0, 1]");
  }
  const r = config.repetition;
  if (!(r.window >= 2)) throw new RangeError("repetition.window must be at least 2");
  if (!(r.warnAfter >= 2)) throw new RangeError("repetition.warnAfter must be at least 2");
  if (!(r.blockAfter >= r.warnAfter)) {
    throw new RangeError("repetition.blockAfter must be >= repetition.warnAfter");
  }
  return config;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warn: 1, block: 2 };

function fmtUsd(n: number): string {
  if (!Number.isFinite(n)) return "unlimited";
  return `$${n.toFixed(n !== 0 && Math.abs(n) < 0.01 ? 5 : 4)}`;
}

export class CostGuard {
  readonly config: ResolvedGuardConfig;
  private readonly sessions = new Map<string, SessionState>();

  constructor(options: GuardOptions = {}) {
    this.config = resolveConfig(options);
  }

  /**
   * Synchronous pre-flight check. Updates session counters unless the result is BLOCK.
   * Does not call the enterprise hook (use `check()` for that).
   */
  evaluate(action: GuardAction): GuardResult {
    return this.run(action, []);
  }

  /** Async pre-flight check that also runs the enterprise hook, if configured. */
  async check(action: GuardAction): Promise<GuardResult> {
    const hook = this.config.enterpriseHook;
    const extra: Finding[] = [];

    if (hook?.extraFindings) {
      try {
        extra.push(...(await hook.extraFindings(action, this.getSession(action.sessionId))));
      } catch (err) {
        extra.push({
          detector: "enterprise",
          ruleId: "hook-error",
          severity: "warn",
          message: `Enterprise hook "${hook.name}" failed while checking policy: ${err instanceof Error ? err.message : String(err)}`,
          remediation: "Check the hook's configuration. Policy checks from the hook were skipped for this step.",
        });
      }
    }

    const { result, event } = this.runWithEvent(action, extra);

    if (hook?.afterDecision) {
      try {
        await hook.afterDecision(event);
      } catch {
        /* Audit failures must never break the guarded application. */
      }
    }
    return result;
  }

  /**
   * Check an action and run `fn` only if it is not blocked.
   * Throws `GuardBlockedError` on BLOCK. `onWarn` is called for WARN results.
   */
  async protect<T>(
    action: GuardAction,
    fn: () => Promise<T> | T,
    opts: { onWarn?: (result: GuardResult) => void } = {},
  ): Promise<T> {
    const result = await this.check(action);
    if (result.decision === "BLOCK") throw new GuardBlockedError(result);
    if (result.decision === "WARN") opts.onWarn?.(result);
    return fn();
  }

  /** Add (or subtract) spend after learning the real cost: pass `actual - estimated`. */
  adjustSpend(deltaUsd: number, sessionId: string = DEFAULT_SESSION_ID): void {
    const s = this.state(sessionId);
    s.spentUsd = Math.max(0, s.spentUsd + deltaUsd);
  }

  getSession(sessionId: string = DEFAULT_SESSION_ID): SessionSnapshot {
    return this.snapshot(sessionId, this.state(sessionId));
  }

  resetSession(sessionId: string = DEFAULT_SESSION_ID): void {
    this.sessions.delete(sessionId);
  }

  /* ------------------------------------------------------------------ */

  private state(sessionId: string): SessionState {
    let s = this.sessions.get(sessionId);
    if (!s) {
      s = { steps: 0, spentUsd: 0, warned: 0, blocked: 0, history: [] };
      this.sessions.set(sessionId, s);
    }
    return s;
  }

  private snapshot(sessionId: string, s: SessionState): SessionSnapshot {
    const { maxSteps, maxBudgetUsd } = this.config;
    return {
      sessionId,
      steps: s.steps,
      maxSteps,
      remainingSteps: Math.max(0, maxSteps - s.steps),
      spentUsd: s.spentUsd,
      maxBudgetUsd,
      remainingBudgetUsd: Math.max(0, maxBudgetUsd - s.spentUsd),
      warned: s.warned,
      blocked: s.blocked,
    };
  }

  private run(action: GuardAction, extra: Finding[]): GuardResult {
    return this.runWithEvent(action, extra).result;
  }

  private runWithEvent(action: GuardAction, extra: Finding[]): { result: GuardResult; event: DecisionEvent } {
    const cfg = this.config;
    const sessionId = action.sessionId ?? DEFAULT_SESSION_ID;
    const s = this.state(sessionId);
    const cost = estimateActionCost(action, cfg);
    const findings: Finding[] = [];

    /* 1. Hard limits: steps and budget */
    const nextSteps = s.steps + 1;
    const nextSpend = s.spentUsd + cost;

    if (nextSteps > cfg.maxSteps) {
      findings.push({
        detector: "limits",
        ruleId: "step-limit",
        severity: "block",
        message: `Step limit reached: this would be step ${nextSteps}, but the maximum is ${cfg.maxSteps}.`,
        remediation:
          "End the task, or raise maxSteps if the extra steps are intentional. If an agent keeps going without finishing, fix its stop condition.",
      });
    } else if (Number.isFinite(cfg.maxSteps) && nextSteps >= cfg.maxSteps * cfg.warnAtRatio) {
      findings.push({
        detector: "limits",
        ruleId: "step-limit-approaching",
        severity: "warn",
        message: `Approaching step limit: step ${nextSteps} of ${cfg.maxSteps}.`,
        remediation: "Wrap up the task or raise maxSteps if the work genuinely needs more steps.",
      });
    }

    if (nextSpend > cfg.maxBudgetUsd + EPSILON) {
      findings.push({
        detector: "limits",
        ruleId: "budget-limit",
        severity: "block",
        message: `Budget exceeded: this step is estimated at ${fmtUsd(cost)}, which would bring session spend to ${fmtUsd(nextSpend)} (limit ${fmtUsd(cfg.maxBudgetUsd)}).`,
        remediation:
          "Use a cheaper model, shorten the prompt or context, lower the expected output size, or raise maxBudgetUsd after review.",
      });
    } else if (
      Number.isFinite(cfg.maxBudgetUsd) &&
      cfg.maxBudgetUsd > 0 &&
      nextSpend >= cfg.maxBudgetUsd * cfg.warnAtRatio
    ) {
      const pct = Math.round((nextSpend / cfg.maxBudgetUsd) * 100);
      findings.push({
        detector: "limits",
        ruleId: "budget-approaching",
        severity: "warn",
        message: `Approaching budget: ${fmtUsd(nextSpend)} of ${fmtUsd(cfg.maxBudgetUsd)} (${pct}%) would be used after this step.`,
        remediation: "Switch to a cheaper model or trim context to stay within budget.",
      });
    }

    /* 2. Content checks */
    findings.push(...detectDangerous(action, cfg.dangerousPatterns));
    findings.push(...detectPii(action.input, cfg.piiRules));

    /* 3. Loop detection */
    const fp = fingerprintAction(action);
    findings.push(...detectRepetition(s.history, fp, cfg.repetition));

    /* 4. Extra findings from the enterprise hook */
    findings.push(...extra);

    /* 5. Decide */
    findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const decision: Decision = findings.some((f) => f.severity === "block")
      ? "BLOCK"
      : findings.some((f) => f.severity === "warn")
        ? "WARN"
        : "ALLOW";

    /* 6. Commit state. Blocked actions never execute, so they are not charged. */
    s.history.push(fp);
    if (s.history.length > HISTORY_CAP) s.history.splice(0, s.history.length - HISTORY_CAP);
    if (decision === "BLOCK") {
      s.blocked++;
    } else {
      s.steps = nextSteps;
      s.spentUsd = nextSpend;
      if (decision === "WARN") s.warned++;
    }

    const snapshot = this.snapshot(sessionId, s);
    const { reason, remediation } = explain(decision, findings, snapshot);
    const timestamp = new Date().toISOString();

    const result: GuardResult = {
      decision,
      reason,
      remediation,
      findings,
      sessionId,
      estimatedCostUsd: cost,
      session: snapshot,
      timestamp,
    };

    const event: DecisionEvent = {
      timestamp,
      sessionId,
      kind: action.kind,
      ...(action.name !== undefined ? { name: action.name } : {}),
      inputPreview: redactSensitive(action.input, cfg.piiRules).replace(/\s+/g, " ").slice(0, 200),
      result,
    };

    if (cfg.onDecision) {
      try {
        cfg.onDecision(event);
      } catch {
        /* Observers must never break the guarded application. */
      }
    }
    return { result, event };
  }
}

function explain(
  decision: Decision,
  findings: Finding[],
  session: SessionSnapshot,
): { reason: string; remediation: string } {
  if (decision === "ALLOW") {
    const steps = Number.isFinite(session.maxSteps) ? `${session.steps}/${session.maxSteps}` : `${session.steps}`;
    return {
      reason: `No risks detected. Step ${steps}, ${fmtUsd(session.spentUsd)} of ${fmtUsd(session.maxBudgetUsd)} budget used.`,
      remediation: "None required.",
    };
  }
  const relevant = findings.filter((f) => f.severity !== "info");
  const top = relevant.filter((f) => f.severity === (decision === "BLOCK" ? "block" : "warn")).slice(0, 3);
  const remediations = [...new Set(top.map((f) => f.remediation))];
  const extra = relevant.length - top.length;
  const more = extra > 0 ? ` (+${extra} more finding${extra === 1 ? "" : "s"})` : "";
  return {
    reason: `${top.map((f) => f.message).join(" ")}${more}`,
    remediation: remediations.join(" "),
  };
}
