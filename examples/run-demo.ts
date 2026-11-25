/**
 * Programmatic demo: a fake agent loop guarded by costguard-ai.
 * Everything is simulated locally: no network, no real LLM, no real commands.
 *
 *   npm run demo
 */

import { CostGuard, GuardBlockedError, MemoryAuditSink, createEnterpriseHook } from "../src/index.js";

const audit = new MemoryAuditSink();

const guard = new CostGuard({
  maxSteps: 10,
  maxBudgetUsd: 0.1,
  repetition: { warnAfter: 3, blockAfter: 4 },
  // Custom rule: internal employee IDs must not leave the company.
  piiRules: [
    {
      id: "employee-id",
      label: "Employee ID",
      pattern: /\bEMP-\d{6}\b/,
      severity: "block",
      remediation: "Replace employee IDs with an anonymised token before sending.",
    },
  ],
  enterpriseHook: createEnterpriseHook({
    environment: "demo",
    sinks: [audit],
  }),
});

// A pretend model call. In real life this would be your LLM client.
async function fakeLlm(prompt: string): Promise<string> {
  return `(simulated answer to: ${prompt.slice(0, 30)}...)`;
}

const prompts = [
  "Summarise our Q3 roadmap.",
  "Summarise our Q3 roadmap.",
  "Summarise our Q3 roadmap.",
  "Summarise our Q3 roadmap.",
  "Why was EMP-004217 flagged by payroll?",
  "Write a haiku about budgets.",
];

for (const prompt of prompts) {
  try {
    const answer = await guard.protect(
      { kind: "llm_call", name: "chat", input: prompt, model: "small-model", outputTokens: 400 },
      () => fakeLlm(prompt),
      { onWarn: (r) => console.log(`  WARN  ${r.reason}`) },
    );
    console.log(`ALLOWED  ${prompt}\n  -> ${answer}`);
  } catch (err) {
    if (err instanceof GuardBlockedError) {
      console.log(`BLOCKED  ${prompt}\n  reason: ${err.result.reason}\n  fix:    ${err.result.remediation}`);
    } else {
      throw err;
    }
  }
}

const s = guard.getSession();
console.log(`\nSession: ${s.steps}/${s.maxSteps} steps, $${s.spentUsd.toFixed(5)} of $${s.maxBudgetUsd} spent`);
console.log(`Audit records captured: ${audit.records.length}`);
console.log(`Last preview (secrets redacted): ${audit.records.at(-1)?.inputPreview}`);
