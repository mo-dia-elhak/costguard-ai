#!/usr/bin/env node
/**
 * costguard CLI
 *
 *   costguard replay examples/*.json
 *   costguard check "rm -rf /" --kind shell_command
 */

import { readFileSync } from "node:fs";
import { CostGuard } from "./guard.js";
import {
  bold,
  colorDecision,
  dim,
  formatReport,
  loadScenario,
  replayScenario,
} from "./replay.js";
import { ACTION_KINDS, type ActionKind, type GuardOptions } from "./types.js";

const HELP = `costguard: pre-execution guardrail for AI apps and agents

Usage:
  costguard replay <scenario.json...> [options]   Replay scenarios locally (no network, nothing executed)
  costguard check <text | -> [options]            Check one action; "-" reads from stdin

Options:
  --kind <kind>        Action kind for "check" (default: custom)
                       one of: ${ACTION_KINDS.join(", ")}
  --max-steps <n>      Override the step limit
  --max-budget <usd>   Override the budget limit in USD
  --json               Machine-readable output
  --no-color           Disable ANSI colors (also honours NO_COLOR)
  --strict             "check": exit 1 on WARN as well as BLOCK
  -v, --version        Print version
  -h, --help           Show this help

Exit codes:
  replay: 0 all expectations met | 1 an expectation failed | 64 usage or file error
  check:  0 ALLOW/WARN | 1 WARN with --strict | 2 BLOCK | 64 usage error
`;

interface Parsed {
  positional: string[];
  flags: Map<string, string | true>;
}

const VALUE_FLAGS = new Set(["--kind", "--max-steps", "--max-budget"]);

function parseArgs(argv: string[]): Parsed {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === "-") {
      positional.push(arg);
    } else if (arg.startsWith("-")) {
      if (VALUE_FLAGS.has(arg)) {
        const value = argv[i + 1];
        if (value === undefined) throw new Error(`Missing value for ${arg}`);
        flags.set(arg, value);
        i++;
      } else {
        flags.set(arg, true);
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function numberFlag(flags: Parsed["flags"], name: string): number | undefined {
  const v = flags.get(name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (typeof v !== "string" || !Number.isFinite(n) || n < 0) {
    throw new Error(`${name} expects a non-negative number`);
  }
  return n;
}

function overridesFrom(flags: Parsed["flags"]): GuardOptions {
  const maxSteps = numberFlag(flags, "--max-steps");
  const maxBudgetUsd = numberFlag(flags, "--max-budget");
  return {
    ...(maxSteps !== undefined ? { maxSteps } : {}),
    ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
  };
}

function version(): string {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    version: string;
  };
  return pkg.version;
}

function main(argv: string[]): number {
  const { positional, flags } = parseArgs(argv);

  if (flags.has("-v") || flags.has("--version")) {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  if (flags.has("-h") || flags.has("--help")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (positional.length === 0) {
    process.stderr.write(HELP);
    return 64;
  }

  const color = !flags.has("--no-color") && !process.env["NO_COLOR"] && Boolean(process.stdout.isTTY);
  const asJson = flags.has("--json");
  const [command, ...rest] = positional;

  if (command === "replay") {
    if (rest.length === 0) throw new Error("replay needs at least one scenario file");
    const overrides = overridesFrom(flags);
    const reports = rest.map((file) => replayScenario(loadScenario(file), overrides));
    if (asJson) {
      process.stdout.write(`${JSON.stringify(reports, null, 2)}\n`);
    } else {
      process.stdout.write(`${reports.map((r) => formatReport(r, { color })).join("\n\n")}\n`);
    }
    return reports.some((r) => r.mismatches > 0) ? 1 : 0;
  }

  if (command === "check") {
    const target = rest[0];
    if (target === undefined) throw new Error('check needs text to inspect (or "-" for stdin)');
    const input = target === "-" ? readFileSync(0, "utf8") : target;
    const kindFlag = flags.get("--kind");
    const kind = (typeof kindFlag === "string" ? kindFlag : "custom") as ActionKind;
    if (!ACTION_KINDS.includes(kind)) throw new Error(`--kind must be one of: ${ACTION_KINDS.join(", ")}`);

    const guard = new CostGuard(overridesFrom(flags));
    const result = guard.evaluate({ kind, input });

    if (asJson) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(`${colorDecision(result.decision, color)} ${bold(result.reason, color)}\n`);
      if (result.decision !== "ALLOW") process.stdout.write(`${dim(`fix: ${result.remediation}`, color)}\n`);
    }
    if (result.decision === "BLOCK") return 2;
    if (result.decision === "WARN" && flags.has("--strict")) return 1;
    return 0;
  }

  throw new Error(`Unknown command "${command}". Run costguard --help.`);
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`costguard: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 64;
}
