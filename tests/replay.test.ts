import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { formatReport, loadScenario, replayScenario, validateScenario } from "../src/index.js";

const examplesDir = new URL("../examples/", import.meta.url);
const scenarioFiles = readdirSync(examplesDir).filter((f) => f.endsWith(".json"));

test("there are bundled example scenarios", () => {
  assert.ok(scenarioFiles.length >= 4);
});

for (const file of scenarioFiles) {
  test(`bundled scenario ${file} matches every expectation`, () => {
    const scenario = loadScenario(new URL(file, examplesDir));
    const report = replayScenario(scenario);
    const failures = report.steps
      .filter((s) => s.matchedExpectation === false)
      .map((s) => `#${s.index} ${s.label}: expected ${s.step.expect}, got ${s.result.decision}`);
    assert.deepEqual(failures, []);
    assert.ok(report.steps.every((s) => s.matchedExpectation !== null), "every example step should declare `expect`");
  });
}

test("replay reports mismatches and formats readable output", () => {
  const report = replayScenario({
    name: "mismatch",
    steps: [{ kind: "shell_command", input: "rm -rf /", expect: "ALLOW" }],
  });
  assert.equal(report.mismatches, 1);
  const text = formatReport(report);
  assert.match(text, /BLOCK/);
  assert.match(text, /expected ALLOW/);
  assert.match(text, /fix:/);
});

test("replay output never contains raw secrets", () => {
  const key = `sk-${"Q".repeat(30)}`;
  const report = replayScenario({ name: "s", steps: [{ kind: "llm_call", input: `key ${key}` }] });
  assert.ok(!formatReport(report).includes(key));
  assert.ok(!JSON.stringify(report.steps.map((s) => s.label)).includes(key));
});

test("overrides win over scenario config", () => {
  const report = replayScenario(
    { name: "o", config: { maxSteps: 100 }, steps: [{ kind: "custom", input: "a" }, { kind: "custom", input: "b" }] },
    { maxSteps: 1 },
  );
  assert.equal(report.steps[1]?.result.decision, "BLOCK");
});

test("scenario config can carry JSON-friendly custom rules", () => {
  const report = replayScenario({
    name: "custom",
    config: {
      piiRules: [{ id: "emp", label: "Employee ID", pattern: "EMP-\\d{6}", flags: "", severity: "block" }],
    },
    steps: [{ kind: "llm_call", input: "look up EMP-123456", expect: "BLOCK" }],
  });
  assert.equal(report.mismatches, 0);
});

test("validateScenario rejects malformed input with clear messages", () => {
  assert.throws(() => validateScenario(null), /JSON object/);
  assert.throws(() => validateScenario({ steps: [] }), /"name"/);
  assert.throws(() => validateScenario({ name: "x", steps: [] }), /steps/);
  assert.throws(() => validateScenario({ name: "x", steps: [{ kind: "nope", input: "" }] }), /steps\[0\]\.kind/);
  assert.throws(() => validateScenario({ name: "x", steps: [{ kind: "custom" }] }), /input/);
  assert.throws(
    () => validateScenario({ name: "x", steps: [{ kind: "custom", input: "", expect: "MAYBE" }] }),
    /expect/,
  );
});
