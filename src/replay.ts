/**
 * Simulation / replay mode.
 *
 * A scenario is a JSON file describing a sequence of actions an agent *would* take.
 * Replaying it runs every step through the guard locally: no network, no paid services,
 * no commands executed. Steps may carry an `expect` decision so scenarios double as tests.
 */

import { readFileSync } from "node:fs";
import { redactSensitive } from "./detectors.js";
import { CostGuard } from "./guard.js";
import {
  ACTION_KINDS,
  type ActionKind,
  type Decision,
  type GuardOptions,
  type GuardResult,
  type SessionSnapshot,
} from "./types.js";

/** Guard options that can be expressed in JSON (no functions or hooks). */
export type ScenarioConfig = Omit<GuardOptions, "onDecision" | "enterpriseHook">;

export interface ReplayStep {
  /** Display label. Defaults to `name`, then a redacted preview of `input`. */
  label?: string;
  sessionId?: string;
  kind: ActionKind;
  name?: string;
  input: string;
  model?: string;
  inputTokens?: number;
  outputTokens?: number;
  estimatedCostUsd?: number;
  /** If set, the replay reports a mismatch when the decision differs. */
  expect?: Decision;
}

export interface ReplayScenario {
  name: string;
  description?: string;
  config?: ScenarioConfig;
  steps: ReplayStep[];
}

export interface ReplayStepResult {
  index: number;
  label: string;
  step: ReplayStep;
  result: GuardResult;
  /** null when the step has no `expect`. */
  matchedExpectation: boolean | null;
}

export interface ReplayReport {
  scenario: string;
  description?: string;
  steps: ReplayStepResult[];
  totals: { allow: number; warn: number; block: number };
  mismatches: number;
  finalSession: SessionSnapshot;
}

const DECISIONS: readonly Decision[] = ["ALLOW", "WARN", "BLOCK"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate untrusted JSON and return a typed scenario. Throws Error with a precise message. */
export function validateScenario(raw: unknown): ReplayScenario {
  if (!isRecord(raw)) throw new Error("Scenario must be a JSON object.");
  if (typeof raw["name"] !== "string" || raw["name"].length === 0) {
    throw new Error('Scenario needs a non-empty string "name".');
  }
  const steps = raw["steps"];
  if (!Array.isArray(steps) || steps.length === 0) {
    throw new Error('Scenario needs a non-empty "steps" array.');
  }
  steps.forEach((s: unknown, i: number) => {
    const at = `steps[${i}]`;
    if (!isRecord(s)) throw new Error(`${at} must be an object.`);
    if (typeof s["kind"] !== "string" || !ACTION_KINDS.includes(s["kind"] as ActionKind)) {
      throw new Error(`${at}.kind must be one of: ${ACTION_KINDS.join(", ")}.`);
    }
    if (typeof s["input"] !== "string") throw new Error(`${at}.input must be a string.`);
    if (s["expect"] !== undefined && !DECISIONS.includes(s["expect"] as Decision)) {
      throw new Error(`${at}.expect must be one of: ${DECISIONS.join(", ")}.`);
    }
  });
  if (raw["config"] !== undefined && !isRecord(raw["config"])) {
    throw new Error('"config" must be an object.');
  }
  return raw as unknown as ReplayScenario;
}

export function loadScenario(path: string | URL): ReplayScenario {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`Cannot read scenario ${String(path)}: ${err instanceof Error ? err.message : String(err)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Invalid JSON in ${String(path)}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return validateScenario(parsed);
}

/** Replay a scenario through a fresh guard. `overrides` win over the scenario's own config. */
export function replayScenario(scenario: ReplayScenario, overrides: GuardOptions = {}): ReplayReport {
  const guard = new CostGuard({ ...scenario.config, ...overrides });
  const results: ReplayStepResult[] = [];
  const totals = { allow: 0, warn: 0, block: 0 };
  let mismatches = 0;

  scenario.steps.forEach((step, index) => {
    const result = guard.evaluate({
      kind: step.kind,
      input: step.input,
      ...(step.sessionId !== undefined ? { sessionId: step.sessionId } : {}),
      ...(step.name !== undefined ? { name: step.name } : {}),
      ...(step.model !== undefined ? { model: step.model } : {}),
      ...(step.inputTokens !== undefined ? { inputTokens: step.inputTokens } : {}),
      ...(step.outputTokens !== undefined ? { outputTokens: step.outputTokens } : {}),
      ...(step.estimatedCostUsd !== undefined ? { estimatedCostUsd: step.estimatedCostUsd } : {}),
    });

    const key = result.decision.toLowerCase() as keyof typeof totals;
    totals[key]++;

    const matched = step.expect === undefined ? null : step.expect === result.decision;
    if (matched === false) mismatches++;

    const preview = redactSensitive(step.input, guard.config.piiRules).replace(/\s+/g, " ");
    results.push({
      index: index + 1,
      label: step.label ?? step.name ?? (preview.length > 44 ? `${preview.slice(0, 43)}\u2026` : preview),
      step,
      result,
      matchedExpectation: matched,
    });
  });

  const last = results[results.length - 1];
  return {
    scenario: scenario.name,
    ...(scenario.description !== undefined ? { description: scenario.description } : {}),
    steps: results,
    totals,
    mismatches,
    finalSession: last ? last.result.session : guard.getSession(),
  };
}

/* -------------------------------------------------------------------------- */
/* Pretty printing                                                            */
/* -------------------------------------------------------------------------- */

const ANSI = { reset: "\u001b[0m", dim: "\u001b[2m", bold: "\u001b[1m", red: "\u001b[31m", green: "\u001b[32m", yellow: "\u001b[33m" };

function paint(enabled: boolean, code: string, text: string): string {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

export function decisionColor(decision: Decision): string {
  return decision === "ALLOW" ? ANSI.green : decision === "WARN" ? ANSI.yellow : ANSI.red;
}

export function colorDecision(decision: Decision, enabled: boolean): string {
  return paint(enabled, decisionColor(decision), decision.padEnd(5));
}

export function dim(text: string, enabled: boolean): string {
  return paint(enabled, ANSI.dim, text);
}

export function bold(text: string, enabled: boolean): string {
  return paint(enabled, ANSI.bold, text);
}

export function formatReport(report: ReplayReport, opts: { color?: boolean } = {}): string {
  const color = opts.color ?? false;
  const lines: string[] = [];
  lines.push(bold(`\u25B6 ${report.scenario}`, color));
  if (report.description) lines.push(dim(`  ${report.description}`, color));
  lines.push("");

  for (const s of report.steps) {
    const { result } = s;
    const cost = `$${result.estimatedCostUsd.toFixed(4)}`;
    const num = `#${s.index}`.padEnd(4);
    const kind = s.step.kind.padEnd(14);
    const mark =
      s.matchedExpectation === null
        ? ""
        : s.matchedExpectation
          ? paint(color, ANSI.green, " \u2713")
          : paint(color, ANSI.red, ` \u2717 expected ${s.step.expect}`);
    lines.push(`  ${num} ${colorDecision(result.decision, color)} ${kind} ${s.label.padEnd(46)} ${cost.padStart(8)}${mark}`);
    if (result.decision !== "ALLOW") {
      lines.push(dim(`         reason: ${result.reason}`, color));
      lines.push(dim(`         fix:    ${result.remediation}`, color));
    }
  }

  const f = report.finalSession;
  lines.push("");
  lines.push(
    `  Summary: ${report.totals.allow} allowed, ${report.totals.warn} warned, ${report.totals.block} blocked` +
      ` | steps used ${f.steps}/${f.maxSteps} | spend $${f.spentUsd.toFixed(4)} of $${f.maxBudgetUsd.toFixed(2)}`,
  );
  if (report.mismatches > 0) {
    lines.push(paint(color, ANSI.red, `  ${report.mismatches} step(s) did not match their expected decision.`));
  }
  return lines.join("\n");
}
