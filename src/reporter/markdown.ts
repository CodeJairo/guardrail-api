import type { AuditReport } from '../engine/runner.js';
import type { Severity } from '../rules/types.js';

export function generateMarkdownReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push('# 🛡️ Guardrail API Security Audit Report');
  lines.push('');
  lines.push(`**Specification:** \`${report.specTitle}\` (\`${report.specSource}\`)  `);
  lines.push(`**OpenAPI Version:** ${report.specVersion}  `);
  if (report.targetUrl) {
    lines.push(`**Target Base URL:** \`${report.targetUrl}\`  `);
  }
  lines.push(`**Scan Timestamp:** ${report.startTime}  `);
  lines.push(`**Scan Duration:** ${report.durationMs}ms  `);
  lines.push(`**Total Operations Analyzed:** ${report.totalOperations}  `);
  lines.push('');

  lines.push('## Summary of Findings');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|:---|:---|');
  lines.push(`| 🔴 **CRITICAL** | ${report.summary.critical} |`);
  lines.push(`| 🟠 **HIGH** | ${report.summary.high} |`);
  lines.push(`| 🟡 **MEDIUM** | ${report.summary.medium} |`);
  lines.push(`| 🔵 **LOW** | ${report.summary.low} |`);
  lines.push(`| ⚪ **INFO** | ${report.summary.info} |`);
  lines.push(`| **Total** | **${report.summary.total}** |`);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('🎉 **No security issues found!** All static rules and dynamic probes passed.');
    return lines.join('\n');
  }

  lines.push('## Detailed Findings');
  lines.push('');

  const severityOrder: Record<Severity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };

  const sortedFindings = [...report.findings].sort(
    (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
  );

  for (const f of sortedFindings) {
    const icon =
      f.severity === 'CRITICAL' ? '🔴' :
      f.severity === 'HIGH' ? '🟠' :
      f.severity === 'MEDIUM' ? '🟡' :
      f.severity === 'LOW' ? '🔵' : '⚪';

    const location = f.path ? `\`${f.method || ''} ${f.path}\`` : 'API Root Specification';

    lines.push(`### ${icon} [${f.ruleId}] ${f.title}`);
    lines.push(`- **Severity:** \`${f.severity}\``);
    lines.push(`- **Category:** \`${f.category}\``);
    lines.push(`- **Location:** ${location}`);
    lines.push(`- **Description:** ${f.message}`);
    lines.push(`- **Remediation:** ${f.remediation}`);
    if (f.details && Object.keys(f.details).length > 0) {
      lines.push(`- **Details:** \`${JSON.stringify(f.details)}\``);
    }
    lines.push('');
  }

  return lines.join('\n');
}
