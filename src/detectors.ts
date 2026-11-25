/**
 * Detectors and helpers: dangerous patterns, secrets/PII, repetition, cost estimation.
 *
 * Everything here is pure and synchronous: no I/O, no network.
 */

import { createHash } from "node:crypto";
import type {
  Finding,
  GuardAction,
  ModelPricing,
  PatternRule,
  PiiRule,
  RepetitionConfig,
} from "./types.js";

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** Compile a rule pattern into a fresh global RegExp (safe to reuse across calls). */
export function compilePattern(pattern: RegExp | string, flags?: string): RegExp {
  if (pattern instanceof RegExp) {
    const f = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
    return new RegExp(pattern.source, f);
  }
  const base = flags ?? "i";
  return new RegExp(pattern, base.includes("g") ? base : `${base}g`);
}

/** Luhn checksum, used to cut false positives on credit-card-like numbers. */
export function luhnCheck(digits: string): boolean {
  if (digits.length === 0) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Mask a sensitive value so findings never leak the full secret. */
export function maskValue(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}\u2026**** (${value.length} chars)`;
}

function truncate(value: string, max: number): string {
  const oneLine = value.replace(/\s+/g, " ");
  return oneLine.length <= max ? oneLine : `${oneLine.slice(0, max - 1)}\u2026`;
}

/** Replace anything matching a PII/secret rule with `[REDACTED:rule-id]`. */
export function redactSensitive(input: string, rules: PiiRule[]): string {
  let out = input;
  for (const rule of rules) {
    out = out.replace(compilePattern(rule.pattern, rule.flags), (m) =>
      rule.validate && !rule.validate(m) ? m : `[REDACTED:${rule.id}]`,
    );
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Default rules                                                              */
/* -------------------------------------------------------------------------- */

export const DEFAULT_DANGEROUS_PATTERNS: PatternRule[] = [
  {
    id: "rm-rf-root",
    pattern:
      /\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/\*?|~\/?\*?|\$HOME\/?\*?|\*)(?=\s|$)/i,
    severity: "block",
    message: "Recursive force-delete of a root, home, or wildcard path.",
    remediation:
      "Delete a specific, narrowly scoped directory instead (for example ./build), and review the path first.",
  },
  {
    id: "fork-bomb",
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    severity: "block",
    message: "Shell fork bomb detected.",
    remediation: "Remove this command. It will exhaust process limits and can hang the machine.",
  },
  {
    id: "disk-wipe",
    pattern: /\b(?:mkfs(?:\.\w+)?\b|dd\s+[^\n]*of=\/dev\/(?:sd|nvme|hd|vd|disk)\w*)/i,
    severity: "block",
    message: "Command can format or overwrite a disk device.",
    remediation: "Never run raw disk writes from an automated flow. Use a disposable VM and explicit human approval.",
  },
  {
    id: "sql-drop",
    pattern: /\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b/i,
    severity: "block",
    message: "Destructive SQL (DROP/TRUNCATE) detected.",
    remediation: "Use a reviewed migration, run it against a backup first, and require human approval.",
  },
  {
    id: "sql-delete-without-where",
    pattern: /\bdelete\s+from\s+[\w."`]+\s*;?\s*$/im,
    severity: "block",
    message: "DELETE without a WHERE clause would remove every row.",
    remediation: "Add a WHERE clause (and run it in a transaction) or use an explicit, reviewed bulk-delete job.",
  },
  {
    id: "reverse-shell",
    pattern: /\bnc\s+[^\n]*-e\s+\/bin\/(?:ba)?sh|\/dev\/tcp\//i,
    severity: "block",
    message: "Possible reverse shell.",
    remediation: "Remove this command. Remote shells must never be opened by an automated flow.",
  },
  {
    id: "credential-exfiltration",
    pattern:
      /\b(?:printenv|env)\b\s*\|\s*(?:curl|wget|nc)\b|\bcat\s+[^\n]*(?:\.ssh\/id_[a-z0-9_]+|\.aws\/credentials|\/etc\/shadow)/i,
    severity: "block",
    message: "Command reads or ships credentials or environment secrets.",
    remediation: "Do not expose credential files or the environment. Pass only the specific values a task needs.",
  },
  {
    id: "pipe-to-shell",
    pattern: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i,
    severity: "warn",
    message: "Downloads a script and pipes it straight into a shell.",
    remediation: "Download the script, inspect it (and pin a checksum), then run it explicitly.",
  },
  {
    id: "chmod-777",
    pattern: /\bchmod\s+(?:-R\s+)?0?777\b/i,
    severity: "warn",
    message: "World-writable permissions (chmod 777).",
    remediation: "Grant the narrowest permissions that work, for example 644 for files or 755 for directories.",
  },
  {
    id: "git-force-push",
    pattern: /\bgit\s+push\b[^\n]*\s(?:--force(?![-\w])|-f\b)/i,
    severity: "warn",
    message: "Force push can overwrite shared history.",
    remediation: "Use --force-with-lease, or open a pull request instead.",
  },
  {
    id: "prompt-injection-phrase",
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    severity: "warn",
    message: "Text contains a common prompt-injection phrase.",
    remediation: "Treat this content as untrusted data. Do not let it change the agent's instructions or tools.",
  },
];

export const DEFAULT_PII_RULES: PiiRule[] = [
  {
    id: "api-key-sk",
    label: "API key (sk-...)",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}/,
    severity: "block",
    remediation: "Remove the key from the prompt/command and load it from an environment variable or secret manager. Rotate it if it has been exposed.",
  },
  {
    id: "aws-access-key",
    label: "AWS access key ID",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    severity: "block",
    remediation: "Remove the key and use IAM roles or a secret manager. Rotate it if it has been exposed.",
  },
  {
    id: "github-token",
    label: "GitHub token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    severity: "block",
    remediation: "Remove the token and revoke it in GitHub settings if it has been exposed.",
  },
  {
    id: "slack-token",
    label: "Slack token",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
    severity: "block",
    remediation: "Remove the token and revoke it in Slack if it has been exposed.",
  },
  {
    id: "private-key",
    label: "Private key block",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
    severity: "block",
    remediation: "Never send private keys to a model or external service. Rotate the key.",
  },
  {
    id: "credit-card",
    label: "Credit card number",
    pattern: /\b(?:\d[ -]?){12,18}\d\b/,
    severity: "block",
    remediation: "Remove or tokenise card numbers before sending. Use your payment provider's vault.",
    validate: (m) => {
      const digits = m.replace(/\D/g, "");
      return digits.length >= 13 && digits.length <= 19 && luhnCheck(digits);
    },
  },
  {
    id: "us-ssn",
    label: "US Social Security number",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
    severity: "block",
    remediation: "Remove or mask the number before sending it anywhere.",
  },
  {
    id: "jwt",
    label: "JSON Web Token",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    severity: "warn",
    remediation: "Strip session tokens from payloads. Tokens in prompts can be replayed by anyone who sees the logs.",
  },
  {
    id: "email",
    label: "Email address",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
    severity: "warn",
    remediation: "Replace personal email addresses with placeholders or hashed identifiers when you can.",
  },
];

/**
 * Illustrative placeholder prices (USD per 1M tokens). These are NOT real provider prices:
 * pass your own table via `pricing` for accurate budgets.
 */
export const DEFAULT_PRICING: Record<string, ModelPricing> = {
  default: { inputPerMillionUsd: 3, outputPerMillionUsd: 15 },
  "large-model": { inputPerMillionUsd: 3, outputPerMillionUsd: 15 },
  "small-model": { inputPerMillionUsd: 0.25, outputPerMillionUsd: 1.25 },
};

/* -------------------------------------------------------------------------- */
/* Pattern + PII detectors                                                    */
/* -------------------------------------------------------------------------- */

export function detectDangerous(action: GuardAction, rules: PatternRule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    if (rule.appliesTo && !rule.appliesTo.includes(action.kind)) continue;
    const m = compilePattern(rule.pattern, rule.flags).exec(action.input);
    if (!m) continue;
    findings.push({
      detector: "dangerous-pattern",
      ruleId: rule.id,
      severity: rule.severity,
      message: rule.message,
      remediation: rule.remediation,
      match: truncate(m[0], 80),
    });
  }
  return findings;
}

export function detectPii(input: string, rules: PiiRule[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    const valid: string[] = [];
    for (const m of input.matchAll(compilePattern(rule.pattern, rule.flags))) {
      if (!rule.validate || rule.validate(m[0])) valid.push(m[0]);
    }
    const first = valid[0];
    if (first === undefined) continue;
    findings.push({
      detector: "pii",
      ruleId: rule.id,
      severity: rule.severity,
      message: `${rule.label} detected (${valid.length} occurrence${valid.length === 1 ? "" : "s"}).`,
      remediation:
        rule.remediation ?? "Remove or mask sensitive data before sending it to a model or external service.",
      match: maskValue(first),
    });
  }
  return findings;
}

/* -------------------------------------------------------------------------- */
/* Repetition / loop detection                                                */
/* -------------------------------------------------------------------------- */

/** Stable short hash of an action, ignoring whitespace and case differences. */
export function fingerprintAction(action: GuardAction): string {
  const normalised = action.input.trim().replace(/\s+/g, " ").toLowerCase();
  return createHash("sha256")
    .update(`${action.kind}\u0000${action.name ?? ""}\u0000${normalised}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * @param history fingerprints of previous attempts in this session (oldest first)
 * @param current fingerprint of the action being checked
 */
export function detectRepetition(
  history: readonly string[],
  current: string,
  cfg: RepetitionConfig,
): Finding[] {
  const recent = history.slice(-cfg.window);
  const occurrences = recent.filter((h) => h === current).length + 1;

  if (occurrences >= cfg.blockAfter) {
    return [
      {
        detector: "repetition",
        ruleId: "repeated-action",
        severity: "block",
        message: `The same action has been attempted ${occurrences} times in the last ${cfg.window} steps (limit ${cfg.blockAfter}). This looks like a loop.`,
        remediation:
          "Stop retrying the identical call. Change the input, add a stop condition or backoff, or hand the task to a human.",
      },
    ];
  }
  if (occurrences >= cfg.warnAfter) {
    return [
      {
        detector: "repetition",
        ruleId: "repeated-action",
        severity: "warn",
        message: `The same action has been attempted ${occurrences} times in the last ${cfg.window} steps. It may be starting to loop.`,
        remediation:
          "Check whether the previous results changed anything. If not, vary the input or end the task.",
      },
    ];
  }

  if (cfg.detectCycles) {
    for (const period of [2, 3]) {
      const needed = period * 3;
      if (history.length < needed - 1) continue;
      const seq = [...history.slice(-(needed - 1)), current];
      let periodic = true;
      for (let i = period; i < seq.length; i++) {
        if (seq[i] !== seq[i - period]) {
          periodic = false;
          break;
        }
      }
      if (periodic && new Set(seq.slice(0, period)).size > 1) {
        return [
          {
            detector: "repetition",
            ruleId: "cycle",
            severity: "warn",
            message: `A cycle of ${period} alternating actions has repeated 3 times (ping-pong loop).`,
            remediation:
              "The agent is bouncing between the same steps without progress. Add a progress check or stop condition.",
          },
        ];
      }
    }
  }
  return [];
}

/* -------------------------------------------------------------------------- */
/* Cost estimation                                                            */
/* -------------------------------------------------------------------------- */

/** Rough token estimate: about 4 characters per token for English text. */
export function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

/** Exact match, then longest prefix match (so "large-model-2" finds "large-model"), then "default". */
export function resolvePricing(
  model: string | undefined,
  table: Record<string, ModelPricing>,
): ModelPricing | undefined {
  if (!model) return table["default"];
  const exact = table[model];
  if (exact) return exact;
  let best: string | undefined;
  for (const key of Object.keys(table)) {
    if (key === "default" || !model.startsWith(key)) continue;
    if (best === undefined || key.length > best.length) best = key;
  }
  return best !== undefined ? table[best] : table["default"];
}

export interface CostEstimationConfig {
  pricing: Record<string, ModelPricing>;
  defaultCostPerStepUsd: number;
  defaultExpectedOutputTokens: number;
}

export function estimateActionCost(action: GuardAction, cfg: CostEstimationConfig): number {
  const explicit = action.estimatedCostUsd;
  if (typeof explicit === "number" && Number.isFinite(explicit) && explicit >= 0) return explicit;

  const looksLikeLlm =
    action.kind === "llm_call" || action.model !== undefined || action.inputTokens !== undefined;
  if (looksLikeLlm) {
    const price = resolvePricing(action.model, cfg.pricing);
    if (price) {
      const inTokens = action.inputTokens ?? estimateTokens(action.input);
      const outTokens = action.outputTokens ?? cfg.defaultExpectedOutputTokens;
      return (
        (inTokens * price.inputPerMillionUsd + outTokens * price.outputPerMillionUsd) / 1_000_000
      );
    }
  }
  return cfg.defaultCostPerStepUsd;
}
