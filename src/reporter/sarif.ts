import type { AuditReport } from '../engine/runner.js';
import type { Finding, Severity } from '../rules/types.js';

export function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' | 'none' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
      return 'note';
    default:
      return 'warning';
  }
}

export function generateSarifReport(report: AuditReport): string {
  // Collect unique rules from findings
  const rulesMap = new Map<string, { id: string; name: string; description: string; defaultLevel: string }>();

  for (const finding of report.findings) {
    if (!rulesMap.has(finding.ruleId)) {
      rulesMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.title.replace(/[^a-zA-Z0-9]/g, ''),
        description: finding.title,
        defaultLevel: severityToSarifLevel(finding.severity),
      });
    }
  }

  const sarifRules = Array.from(rulesMap.values()).map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: {
      text: r.description,
    },
    defaultConfiguration: {
      level: r.defaultLevel,
    },
  }));

  const results = report.findings.map((finding: Finding) => {
    const loc = finding.path ? `${finding.method ? finding.method + ' ' : ''}${finding.path}` : 'root';
    return {
      ruleId: finding.ruleId,
      level: severityToSarifLevel(finding.severity),
      message: {
        text: `[${finding.severity}] ${finding.title}: ${finding.message} Remediation: ${finding.remediation}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: report.specSource,
            },
          },
          logicalLocations: [
            {
              name: loc,
              kind: 'endpoint',
            },
          ],
        },
      ],
      properties: {
        category: finding.category,
        severity: finding.severity,
        remediation: finding.remediation,
        details: finding.details,
      },
    };
  });

  const sarifObject = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'guardrail-api',
            version: '1.0.0',
            informationUri: 'https://github.com/codejairo/api-security-cli',
            rules: sarifRules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.startTime,
            endTimeUtc: report.endTime,
          },
        ],
        results,
      },
    ],
  };

  return JSON.stringify(sarifObject, null, 2);
}
