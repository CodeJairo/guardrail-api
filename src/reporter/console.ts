import pc from 'picocolors';
import Table from 'cli-table3';
import type { AuditReport } from '../engine/runner.js';
import type { Finding, Severity } from '../rules/types.js';

export function formatSeverityBadge(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.red(pc.bold(' HIGH '));
    case 'MEDIUM':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'LOW':
      return pc.cyan(pc.bold(' LOW '));
    case 'INFO':
      return pc.gray(' INFO ');
  }
}

export function printConsoleReport(report: AuditReport, failed: boolean, failThreshold: Severity): void {
  console.log('\n' + pc.bold(pc.cyan('━'.repeat(70))));
  console.log(pc.bold(pc.cyan('🛡️  GUARDRAIL API SECURITY AUDIT')));
  console.log(pc.bold(pc.cyan('━'.repeat(70))));

  console.log(`${pc.bold('Specification:')}  ${pc.white(report.specTitle)} (${pc.dim(report.specSource)})`);
  console.log(`${pc.bold('OpenAPI Version:')} ${report.specVersion}`);
  if (report.targetUrl) {
    console.log(`${pc.bold('Target API:')}     ${pc.green(report.targetUrl)}`);
  }
  console.log(`${pc.bold('Duration:')}       ${report.durationMs}ms`);
  console.log(`${pc.bold('Operations:')}     ${report.totalOperations} endpoints analyzed\n`);

  // Summary Metrics Table
  const table = new Table({
    head: [
      pc.bold(pc.red('CRITICAL')),
      pc.bold(pc.redBright('HIGH')),
      pc.bold(pc.yellow('MEDIUM')),
      pc.bold(pc.cyan('LOW')),
      pc.bold(pc.gray('INFO')),
      pc.bold('TOTAL'),
    ],
    colWidths: [12, 10, 11, 10, 10, 10],
  });

  table.push([
    report.summary.critical > 0 ? pc.bold(pc.red(report.summary.critical.toString())) : pc.green('0'),
    report.summary.high > 0 ? pc.bold(pc.redBright(report.summary.high.toString())) : pc.green('0'),
    report.summary.medium > 0 ? pc.bold(pc.yellow(report.summary.medium.toString())) : pc.green('0'),
    report.summary.low > 0 ? pc.bold(pc.cyan(report.summary.low.toString())) : pc.green('0'),
    report.summary.info.toString(),
    pc.bold(report.summary.total.toString()),
  ]);

  console.log(table.toString() + '\n');

  // Print Findings
  if (report.findings.length === 0) {
    console.log(pc.green(pc.bold('✨ No security issues detected. Your API specification and endpoints look secure!')));
  } else {
    console.log(pc.bold(pc.underline('Security Findings:\n')));

    // Sort by severity (Critical first)
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

    for (const finding of sortedFindings) {
      const badge = formatSeverityBadge(finding.severity);
      const loc = finding.path ? `${pc.bold(finding.method || '')} ${finding.path}` : 'Specification Root';
      
      console.log(`${badge} [${pc.dim(finding.ruleId)}] ${pc.bold(finding.title)}`);
      console.log(`   ${pc.dim('Location:')}     ${loc}`);
      console.log(`   ${pc.dim('Category:')}     ${finding.category}`);
      console.log(`   ${pc.dim('Description:')}  ${finding.message}`);
      console.log(`   ${pc.green('Remediation:')}  ${finding.remediation}`);
      if (finding.details && Object.keys(finding.details).length > 0) {
        console.log(`   ${pc.dim('Details:')}      ${JSON.stringify(finding.details)}`);
      }
      console.log('');
    }
  }

  // Final CI/CD Status
  console.log(pc.bold(pc.cyan('━'.repeat(70))));
  if (failed) {
    console.log(
      pc.red(pc.bold(`❌ AUDIT FAILED: Security findings equal or exceed threshold '${failThreshold}'.`))
    );
  } else {
    console.log(pc.green(pc.bold('✅ AUDIT PASSED: No security issues exceeding threshold were found.')));
  }
  console.log(pc.bold(pc.cyan('━'.repeat(70))) + '\n');
}
