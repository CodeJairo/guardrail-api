import { buildEndpointUrl } from '../../engine/http-client.js';
import type { DynamicContext, DynamicRule, Finding } from '../types.js';

export const unauthenticatedProbeRule: DynamicRule = {
  id: 'DY-001',
  name: 'Missing Authentication Enforcement',
  description: 'Verifies that operations marked with security schemes properly reject unauthenticated requests with HTTP 401 or 403',
  defaultSeverity: 'CRITICAL',
  async run(context: DynamicContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { spec, client } = context;

    // Filter operations that declare security
    const securedOperations = spec.operations.filter(
      (op) => op.security && op.security.length > 0
    );

    for (const op of securedOperations) {
      const url = buildEndpointUrl(op.path);
      const method = op.method.toUpperCase();

      try {
        const response = await client.request({
          method: op.method,
          url,
          headers: {
            // Explicitly do not send Authorization header
            'Content-Type': 'application/json',
          },
          data: ['post', 'put', 'patch'].includes(op.method) ? {} : undefined,
        });

        // If API responds with 2xx, authentication is completely missing or bypassed
        if (response.status >= 200 && response.status < 300) {
          findings.push({
            ruleId: 'DY-001',
            title: 'Authentication Bypass / Unprotected Secured Endpoint',
            severity: 'CRITICAL',
            category: 'dynamic',
            path: op.path,
            method,
            message: `Endpoint ${method} ${op.path} is documented to require authentication (${op.security?.map((s) => s.name).join(', ')}), but returned HTTP ${response.status} OK when accessed without credentials.`,
            remediation: 'Enforce authentication middleware on this route to ensure requests without valid tokens return HTTP 401 Unauthorized or 403 Forbidden.',
            reproduction: `curl -i -X ${method} "${context.targetUrl.replace(/\/+$/, '')}${url}"`,
            details: {
              statusCode: response.status,
              securityRequirements: op.security,
            },
          });
        }
      } catch (err: any) {
        // If connection fails or timeouts, record in details if needed or let scan continue
      }
    }

    return findings;
  },
};
