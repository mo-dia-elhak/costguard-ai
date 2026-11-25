# costguard-ai

**A pre-flight guardrail for AI apps and agents.** Inspect every LLM call, tool call, shell command, or query *before* it runs, and get a clear `ALLOW`, `WARN`, or `BLOCK` with a reason and a suggested fix.

Repository: https://github.com/mo-dia-elhak/costguard-ai

License: BSL 1.1 (becomes MIT after the Change Date) · Node 20+ · Zero runtime dependencies

---

## The problem

Autonomous agents fail in boring, expensive ways:

- **A loop burns your budget.** An agent retries the same failing search 400 times overnight.
- **A bad command runs.** A coding agent proposes `rm -rf /` or `DROP TABLE users` and nothing stands in the way.
- **Secrets leak into prompts.** An API key, a customer email, or a card number gets pasted into a model call and lands in someone else's logs.
- **Nobody knows why.** By the time you notice, the money is spent and the data is gone.

Most tooling reports these problems *after* they happen. costguard-ai stops them *before* execution.

## The solution

costguard-ai sits between your agent and the outside world. Before anything executes, you ask the guard:

```ts
const result = guard.evaluate({ kind: "shell_command", input: "rm -rf /" });
// result.decision    -> "BLOCK"
// result.reason      -> "Recursive force-delete of a root, home, or wildcard path."
// result.remediation -> "Delete a specific, narrowly scoped directory instead (for example ./build), and review the path first."
```

| Check | What it does |
| --- | --- |
| **Step limit** | Caps the number of actions per session; warns at 80% by default. |
| **Budget limit** | Estimates cost per action (explicit, token-based, or from text length) and blocks anything that would exceed the session budget. Blocked actions are never charged. |
| **Loop detection** | Warns, then blocks, when the same action repeats within a window. Also catches A, B, A, B ping-pong cycles. |
| **Dangerous patterns** | Built-in rules for destructive shell and SQL, reverse shells, credential exfiltration, `curl \| sh`, force pushes, and common prompt-injection phrases. |
| **Secrets and PII** | API keys, AWS and GitHub tokens, private keys, JWTs, emails, US SSNs, and Luhn-validated card numbers. Findings only ever show masked excerpts. |
| **Custom rules** | Add, override, or disable any rule by id. Rules can be plain JSON. |
| **Simulation / replay** | Run whole scenarios offline: no network, no paid services, nothing executed. |
| **Enterprise hook** | Audit sinks (memory, JSONL, webhook) and an organisation-policy callback. |

Zero runtime dependencies. Everything runs locally.

## Quickstart

```bash
git clone https://github.com/mo-dia-elhak/costguard-ai.git
cd costguard-ai
npm install
```

### 1. Try it without writing code (simulation mode)

```bash
npm run replay          # replays every scenario in examples/
npm run demo            # a guarded fake agent loop (examples/run-demo.ts)
```

No API keys, no network, no real commands. Every scenario step carries an `expect`, so replays double as regression tests and exit with code `1` if a decision changes.

### 2. Check a single action from the CLI

```bash
npx tsx src/cli.ts check "rm -rf /" --kind shell_command
npx tsx src/cli.ts check "mail bob@example.com" --strict   # exit 1 on WARN
echo "some prompt" | npx tsx src/cli.ts check -
```

After `npm run build`, the same commands are available as `costguard` (`node dist/cli.js`).

### 3. Use it as a library

```ts
import { CostGuard, GuardBlockedError } from "costguard-ai";

const guard = new CostGuard({
  maxSteps: 20,
  maxBudgetUsd: 0.5,
  pricing: { "my-model": { inputPerMillionUsd: 3, outputPerMillionUsd: 15 } },
});

try {
  const answer = await guard.protect(
    { kind: "llm_call", model: "my-model", input: prompt, outputTokens: 800 },
    () => callMyLlm(prompt),                       // only runs if not BLOCKED
    { onWarn: (r) => console.warn(r.reason) },     // runs on WARN, then proceeds
  );
} catch (err) {
  if (err instanceof GuardBlockedError) {
    console.error(err.result.reason, err.result.remediation);
  }
}
```

Prefer to manage control flow yourself? Call `guard.evaluate(action)` (sync) or `await guard.check(action)` (async, runs the enterprise hook) and branch on `result.decision`.

## Sample output

Real output from `npm run replay` (colors omitted, a few lines trimmed for length):

```text
▶ Runaway agent: repeated search, then a budget overrun
  An agent keeps repeating the same web search, then tries a large summarisation call that would break the budget.

  #1   ALLOW llm_call       plan                                            $0.0200 ✓
  #2   ALLOW tool_call      web_search                                      $0.0100 ✓
  #3   ALLOW tool_call      web_search                                      $0.0100 ✓
  #4   WARN  tool_call      web_search                                      $0.0100 ✓
         reason: The same action has been attempted 3 times in the last 10 steps. It may be starting to loop.
         fix:    Check whether the previous results changed anything. If not, vary the input or end the task.
  #5   WARN  tool_call      web_search                                      $0.0100 ✓
  #6   BLOCK tool_call      web_search                                      $0.0100 ✓
         reason: The same action has been attempted 5 times in the last 10 steps (limit 5). This looks like a loop.
         fix:    Stop retrying the identical call. Change the input, add a stop condition or backoff, or hand the task to a human.
  #7   ALLOW llm_call       summarise                                       $0.3000 ✓
  #8   BLOCK llm_call       write_report                                    $0.2000 ✓
         reason: Budget exceeded: this step is estimated at $0.2000, which would bring session spend to $0.5600 (limit $0.5000).
         fix:    Use a cheaper model, shorten the prompt or context, lower the expected output size, or raise maxBudgetUsd after review.

  Summary: 4 allowed, 2 warned, 2 blocked | steps used 6/12 | spend $0.3600 of $0.50
```

```text
▶ Leaky prompts: secrets and personal data

  #1   ALLOW llm_call       clean prompt                                    $0.0100 ✓
  #2   WARN  llm_call       prompt with email                               $0.0100 ✓
         reason: Email address detected (1 occurrence).
         fix:    Replace personal email addresses with placeholders or hashed identifiers when you can.
  #3   BLOCK llm_call       prompt with API key                             $0.0100 ✓
         reason: API key (sk- prefix) detected (1 occurrence).
         fix:    Remove the key from the prompt/command and load it from an environment variable or secret manager. Rotate it if it has been exposed.
  #4   BLOCK llm_call       prompt with card number                         $0.0100 ✓
  #6   ALLOW llm_call       order number (not a card)                       $0.0100 ✓
```

And from the CLI:

```text
$ costguard check "rm -rf /" --kind shell_command
BLOCK Recursive force-delete of a root, home, or wildcard path.
fix: Delete a specific, narrowly scoped directory instead (for example ./build), and review the path first.
```

The `GuardResult` object (also available as `--json`) contains `decision`, `reason`, `remediation`, a list of `findings` (each with `ruleId`, `severity`, `message`, `remediation`, and a masked `match`), the action's `estimatedCostUsd`, and a `session` snapshot.

## How decisions are made

1. Findings are collected from limits, dangerous patterns, secrets/PII, loop detection, and the optional enterprise hook.
2. Any `block` finding gives **BLOCK**. Otherwise any `warn` finding gives **WARN**. Otherwise **ALLOW**.
3. `ALLOW` and `WARN` actions count toward the session's steps and budget. `BLOCK` actions do not, because they never execute. They still count toward loop detection, so an agent that keeps hammering a blocked action stays blocked.

## Configuration

```ts
new CostGuard({
  maxSteps: 25,                  // per session
  maxBudgetUsd: 1,               // per session
  warnAtRatio: 0.8,              // WARN at 80% of either limit
  defaultCostPerStepUsd: 0,      // cost for actions with no cost information
  defaultExpectedOutputTokens: 500,
  pricing: { "my-model": { inputPerMillionUsd: 3, outputPerMillionUsd: 15 } },
  repetition: { window: 10, warnAfter: 3, blockAfter: 5, detectCycles: true },
  disabledRules: ["pipe-to-shell"],
  dangerousPatterns: [/* PatternRule[] */],
  piiRules: [/* PiiRule[] */],
  onDecision: (event) => {},     // sync observer, receives redacted previews
  enterpriseHook: undefined,     // see below
});
```

Use a different `sessionId` on each action to keep budgets, step counts, and loop history separate per user or task. Call `guard.adjustSpend(actual - estimated, sessionId)` once you know the real cost of a call.

**Cost estimation order:** explicit `estimatedCostUsd`, then token counts × the pricing table (falling back to ~4 characters per token), then `defaultCostPerStepUsd`. The built-in pricing table contains **illustrative placeholder prices**, not real provider rates. Always pass your own.

### Custom rules

```ts
const guard = new CostGuard({
  piiRules: [
    {
      id: "employee-id",
      label: "Employee ID",
      pattern: /\bEMP-\d{6}\b/,
      severity: "block",
      remediation: "Replace employee IDs with an anonymised token.",
    },
  ],
  dangerousPatterns: [
    {
      id: "no-prod-db",
      pattern: "psql .*prod-db",
      severity: "block",
      message: "Direct access to the production database.",
      remediation: "Use the staging database or request approval.",
      appliesTo: ["shell_command"],
    },
  ],
});
```

A rule whose `id` matches a built-in replaces it. Patterns can be strings (compiled with `flags`, default `"i"`), which keeps rules usable from JSON scenario files.

## Simulation / replay mode

A scenario is a JSON file:

```json
{
  "name": "My scenario",
  "description": "Optional text",
  "config": { "maxSteps": 12, "maxBudgetUsd": 0.5 },
  "steps": [
    { "kind": "shell_command", "input": "rm -rf /", "expect": "BLOCK" },
    { "kind": "llm_call", "model": "large-model", "inputTokens": 100000,
      "outputTokens": 10000, "label": "big call", "expect": "ALLOW" }
  ]
}
```

```bash
costguard replay my-scenario.json             # human-readable
costguard replay my-scenario.json --json      # machine-readable
costguard replay my-scenario.json --max-budget 0.1
```

Replays run through exactly the same guard code as production. Nothing is executed and nothing touches the network. Raw secrets are never printed: labels and previews are redacted. Bundled scenarios live in [`examples/`](examples/) and are verified in CI.

Programmatically: `replayScenario(loadScenario("file.json"))` returns a `ReplayReport`.

## Enterprise hook

```ts
import { CostGuard, JsonlAuditSink, createEnterpriseHook } from "costguard-ai";

const guard = new CostGuard({
  enterpriseHook: createEnterpriseHook({
    environment: "production",
    sinks: [new JsonlAuditSink("./audit-log.jsonl")],
    policy: (action) =>
      action.name === "delete_customer"
        ? [{ detector: "enterprise", ruleId: "needs-approval", severity: "block",
             message: "delete_customer requires human approval.",
             remediation: "Route this action through the approval queue." }]
        : [],
  }),
});

await guard.check(action);   // runs policy first, writes an audit record after
```

The hook is the extension point for teams: audit records contain a **redacted** input preview, never raw secrets. Sinks run independently, and a failing sink or policy callback never crashes your application (a failing policy adds a `WARN` finding so the failure is visible). The bundled sinks are reference implementations; central policy management, SSO, and dashboards are what the commercial offering is for (see below).

## Project layout

```text
src/
  index.ts            public API
  guard.ts            CostGuard: limits, decisions, sessions, protect()
  detectors.ts        dangerous patterns, PII, repetition, cost estimation
  types.ts            all public types
  enterprise-hook.ts  audit sinks + policy extension point
  replay.ts           simulation / replay engine
  cli.ts              `costguard` command
tests/                node:test suites (run with `npm test`)
examples/             replay scenarios + programmatic demo
```

Scripts: `npm run build`, `npm test`, `npm run lint`, `npm run typecheck`, `npm run replay`, `npm run demo`.

## Limitations

costguard-ai is a **safety net, not a security boundary**.

- Pattern and PII detection are heuristic. Expect both false positives and false negatives, and tune rules for your environment.
- Cost figures are **estimates**. Token counts from text length are approximate, and the default pricing table is a placeholder.
- It only sees what you hand it. It cannot stop an action you never route through the guard.
- Session state is held in memory per `CostGuard` instance. Share one instance per process, and persist or aggregate externally if you run multiple workers.
- Keep real sandboxing, least-privilege credentials, and human approval for high-risk operations. Use this alongside them, not instead of them.

## License and commercial use

costguard-ai is licensed under the **Business Source License 1.1** (see [`LICENSE`](LICENSE)). It is *source-available*, not OSI-approved open source, and it **converts to the MIT License** on the Change Date (2029-11-24 for v0.1.0, three years after release; each later version gets its own Change Date). The LICENSE file is the authoritative text. This summary is not legal advice.

| Use | Free | Commercial license required |
| --- | :---: | :---: |
| Personal, hobby, and learning projects | ✅ | |
| Education and academic research | ✅ | |
| Registered non-profits (own internal use) | ✅ | |
| Evaluating costguard-ai (up to 60 days) | ✅ | |
| Development and testing in non-production environments | ✅ | |
| Reading, forking, modifying, and contributing | ✅ | |
| Production use by a company, team, or enterprise | | ✅ |
| Embedding in a product or service you sell or offer to customers | | ✅ |
| Hosted, managed, or SaaS offerings built on costguard-ai | | ✅ |

### Commercial License

A Commercial License covers teams, enterprises, and hosted offerings, and is the home for the work that organisations need around the core guard: central policy and rule management, audit export to your SIEM, single sign-on, support, and an SLA. Contact **dia.elhak@engineer.com** to discuss terms.

If you are unsure which side of the line you are on, ask. Licensing questions are welcome, and for small teams an inexpensive arrangement is usually straightforward.

## Contributing

Issues and pull requests are welcome. Please run `npm run lint && npm run typecheck && npm test` before submitting, and add a test (or a replay scenario with `expect` values) for any new rule. By contributing you agree your contribution is provided under the same license as the project.
