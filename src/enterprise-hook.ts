/**
 * Enterprise hook: the extension point for team and organisation needs.
 *
 * This file ships a small *reference implementation*: audit sinks (memory, JSONL file,
 * webhook) and an optional custom-policy callback. It is where commercial
 * integrations (central policy, SSO, SIEM export, dashboards) plug in.
 *
 * Nothing in this file is called unless you pass the hook to `new CostGuard({ enterpriseHook })`
 * and use `guard.check()` / `guard.protect()`. The webhook sink is the only code that
 * touches the network, and only if you construct it.
 */

import { appendFile } from "node:fs/promises";
import type { DecisionEvent, EnterpriseHook, Finding, GuardAction, SessionSnapshot } from "./types.js";

/** A decision event plus deployment metadata. */
export interface AuditRecord extends DecisionEvent {
  hook: string;
  environment?: string;
  /** True when a license key was supplied to the hook. The key itself is never written to audit records. */
  licenseKeyPresent: boolean;
}

export interface AuditSink {
  write(record: AuditRecord): Promise<void> | void;
}

/** Keeps records in memory. Handy for tests and dashboards. */
export class MemoryAuditSink implements AuditSink {
  readonly records: AuditRecord[] = [];
  write(record: AuditRecord): void {
    this.records.push(record);
  }
}

/** Appends one JSON object per line to a file. Input previews are already redacted. */
export class JsonlAuditSink implements AuditSink {
  constructor(private readonly filePath: string) {}
  async write(record: AuditRecord): Promise<void> {
    await appendFile(this.filePath, `${JSON.stringify(record)}\n`, "utf8");
  }
}

/** POSTs each record as JSON to a URL you control (SIEM collector, internal service, ...). */
export class WebhookAuditSink implements AuditSink {
  constructor(
    private readonly url: string,
    private readonly headers: Record<string, string> = {},
    private readonly timeoutMs = 3000,
  ) {}
  async write(record: AuditRecord): Promise<void> {
    await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json", ...this.headers },
      body: JSON.stringify(record),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }
}

export interface EnterpriseHookOptions {
  /** Your commercial license key, if you have one. Only its presence is recorded. */
  licenseKey?: string;
  /** Free-form label such as "production" or "staging". Added to audit records. */
  environment?: string;
  /** Where decisions are written. Sink errors are isolated: one failing sink never blocks the others. */
  sinks?: AuditSink[];
  /** Organisation-wide policy. Return extra findings to warn or block actions. */
  policy?: (action: GuardAction, session: SessionSnapshot) => Promise<Finding[]> | Finding[];
  /** Hook name shown in findings and audit records. Default "costguard-enterprise". */
  name?: string;
}

export function createEnterpriseHook(options: EnterpriseHookOptions = {}): EnterpriseHook {
  const name = options.name ?? "costguard-enterprise";
  const sinks = options.sinks ?? [];
  const licenseKeyPresent = Boolean(options.licenseKey);
  const { policy, environment } = options;

  return {
    name,
    ...(policy ? { extraFindings: (action, session) => policy(action, session) } : {}),
    async afterDecision(event) {
      const record: AuditRecord = {
        ...event,
        hook: name,
        licenseKeyPresent,
        ...(environment !== undefined ? { environment } : {}),
      };
      await Promise.allSettled(sinks.map(async (sink) => sink.write(record)));
    },
  };
}
