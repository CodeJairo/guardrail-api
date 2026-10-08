import type { AuditReport } from '../engine/runner.js';

export function generateJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
