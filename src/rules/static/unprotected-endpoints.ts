import type { Finding, StaticContext, StaticRule } from '../types.js';

const SENSITIVE_KEYWORDS = [
  'admin',
  'user',
  'users',
  'account',
  'accounts',
  'role',
  'roles',
  'permission',
  'billing',
  'payment',
  'internal',
  'key',
  'keys',
  'token',
  'tokens',
  'secret',
  'credential',
  'pass',
  'password',
  'config',
  'setting',
  'settings',
];

export const unprotectedEndpointsRule: StaticRule = {
  id: 'ST-003',
  name: 'Unprotected Sensitive or Destructive Endpoints',
  description: 'Identifies sensitive or administrative endpoints exposed without authentication or role restrictions',
  defaultSeverity: 'CRITICAL',
  run(context: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const { spec } = context;

    for (const op of spec.operations) {
      const isSecured = Boolean(op.security && op.security.length > 0);
      const method = op.method.toUpperCase();
      const pathLower = op.path.toLowerCase();

      // Check if path contains sensitive keywords
      const matchedKeyword = SENSITIVE_KEYWORDS.find((keyword) => {
        const regex = new RegExp(`(^|[/_\\-])${keyword}([/_\\-]|$)`, 'i');
        return regex.test(pathLower);
      });

      if (!isSecured && matchedKeyword) {
        findings.push({
          ruleId: 'ST-003',
          title: 'Sensitive Endpoint Exposed Without Security Constraints',
          severity: 'CRITICAL',
          category: 'static',
          path: op.path,
          method,
          message: `Endpoint ${method} ${op.path} handles sensitive resources (matches keyword '${matchedKeyword}') but has no authentication or authorization constraints declared.`,
          remediation: `Protect ${method} ${op.path} with strong authentication and role-based access control (RBAC).`,
          details: { keyword: matchedKeyword },
        });
      } else if (!isSecured && ['DELETE', 'PUT', 'PATCH'].includes(method)) {
        findings.push({
          ruleId: 'ST-003',
          title: 'State-Modifying Operation Exposed Without Authentication',
          severity: 'HIGH',
          category: 'static',
          path: op.path,
          method,
          message: `Destructive/mutating HTTP method ${method} on ${op.path} is publicly accessible without authentication.`,
          remediation: `Require authentication (JWT/Bearer or API Key) for mutating operations like ${method}.`,
        });
      }
    }

    return findings;
  },
};
