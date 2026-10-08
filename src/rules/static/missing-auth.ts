import type { Finding, StaticContext, StaticRule } from '../types.js';

export const missingAuthRule: StaticRule = {
  id: 'ST-001',
  name: 'Missing Authentication Scheme',
  description: 'Verifies that operations define authentication schemes (JWT/Bearer, API Keys, etc.)',
  defaultSeverity: 'HIGH',
  run(context: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const { spec } = context;

    const hasGlobalSecuritySchemes = Object.keys(spec.securitySchemes || {}).length > 0;

    if (!hasGlobalSecuritySchemes) {
      findings.push({
        ruleId: 'ST-001',
        title: 'No Security Schemes Defined in Specification',
        severity: 'CRITICAL',
        category: 'static',
        message: 'The OpenAPI specification does not define any security schemes in components.securitySchemes (or securityDefinitions).',
        remediation: 'Define at least one security scheme (such as HTTP Bearer JWT or ApiKey) in components.securitySchemes and apply it globally or to protected operations.',
      });
    }

    for (const op of spec.operations) {
      const isSecured = Boolean(op.security && op.security.length > 0);

      if (!isSecured) {
        findings.push({
          ruleId: 'ST-001',
          title: 'Operation Missing Authentication Requirement',
          severity: 'HIGH',
          category: 'static',
          path: op.path,
          method: op.method.toUpperCase(),
          message: `Operation ${op.method.toUpperCase()} ${op.path} is publicly accessible without any security requirement declared.`,
          remediation: `Configure the 'security' property for operation ${op.method.toUpperCase()} ${op.path} or declare global security at the root of the specification.`,
          details: {
            operationId: op.operationId,
            summary: op.summary,
          },
        });
      }
    }

    return findings;
  },
};
