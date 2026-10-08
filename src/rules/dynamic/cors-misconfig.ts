import { buildEndpointUrl } from '../../engine/http-client.js';
import type { DynamicContext, DynamicRule, Finding } from '../types.js';

const MALICIOUS_ORIGIN = 'https://malicious-domain.com';

export const corsMisconfigRule: DynamicRule = {
  id: 'DY-003',
  name: 'CORS Misconfiguration Check',
  description: 'Verifies whether the API improperly permits untrusted origins or exposes credentials to arbitrary origins',
  defaultSeverity: 'HIGH',
  async run(context: DynamicContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { spec, client } = context;

    // Pick first available GET or POST operation or fallback to root '/'
    const op = spec.operations.find((o) => ['get', 'post'].includes(o.method));
    const testPath = op ? buildEndpointUrl(op.path) : '/';

    try {
      // 1. Send normal GET/POST with malicious Origin header
      const response = await client.request({
        method: op?.method || 'get',
        url: testPath,
        headers: {
          Origin: MALICIOUS_ORIGIN,
        },
      });

      const acao = response.headers['access-control-allow-origin'];
      const acac = response.headers['access-control-allow-credentials'];
      const allowsCredentials = String(acac).toLowerCase() === 'true';

      if (acao) {
        const allowOriginStr = String(acao).trim();

        // Check if malicious origin was reflected back
        if (allowOriginStr === MALICIOUS_ORIGIN) {
          if (allowsCredentials) {
            findings.push({
              ruleId: 'DY-003',
              title: 'Critical CORS Misconfiguration: Origin Reflection with Credentials',
              severity: 'CRITICAL',
              category: 'dynamic',
              path: testPath,
              message: `The server reflects arbitrary origins (${MALICIOUS_ORIGIN}) and allows credentials ('Access-Control-Allow-Credentials: true'). Attackers can read sensitive authenticated user data via CSRF-like JavaScript payloads.`,
              remediation: "Maintain a strict whitelist of trusted origins and never blindly reflect the incoming 'Origin' header when credentials are supported.",
              details: {
                'Access-Control-Allow-Origin': allowOriginStr,
                'Access-Control-Allow-Credentials': acac,
              },
            });
          } else {
            findings.push({
              ruleId: 'DY-003',
              title: 'CORS Arbitrary Origin Reflection',
              severity: 'HIGH',
              category: 'dynamic',
              path: testPath,
              message: `The server reflects untrusted origin '${MALICIOUS_ORIGIN}' in 'Access-Control-Allow-Origin'.`,
              remediation: "Validate the 'Origin' request header against an explicit list of trusted domains before setting 'Access-Control-Allow-Origin'.",
              details: { 'Access-Control-Allow-Origin': allowOriginStr },
            });
          }
        } else if (allowOriginStr === '*') {
          if (allowsCredentials) {
            findings.push({
              ruleId: 'DY-003',
              title: 'Invalid Permissive CORS Policy with Credentials',
              severity: 'HIGH',
              category: 'dynamic',
              path: testPath,
              message: "The server returns 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. This is an invalid and insecure configuration.",
              remediation: "Disallow wildcard '*' origin if credentials (cookies/tokens) are allowed.",
            });
          } else if (op?.security && op.security.length > 0) {
            findings.push({
              ruleId: 'DY-003',
              title: 'Wildcard CORS Header on Authenticated Endpoint',
              severity: 'MEDIUM',
              category: 'dynamic',
              path: testPath,
              message: `Protected endpoint ${op.method.toUpperCase()} ${testPath} permits all external domains via 'Access-Control-Allow-Origin: *'.`,
              remediation: "Restrict 'Access-Control-Allow-Origin' to trusted frontend application domains.",
            });
          }
        }
      }

      // 2. Preflight OPTIONS probe
      const preflight = await client.request({
        method: 'options',
        url: testPath,
        headers: {
          Origin: MALICIOUS_ORIGIN,
          'Access-Control-Request-Method': op?.method.toUpperCase() || 'GET',
          'Access-Control-Request-Headers': 'Authorization,Content-Type',
        },
      });

      const preflightAcao = preflight.headers['access-control-allow-origin'];
      if (preflightAcao === MALICIOUS_ORIGIN && !findings.some((f) => f.title.includes('Reflection'))) {
        findings.push({
          ruleId: 'DY-003',
          title: 'CORS Preflight Reflects Arbitrary Origin',
          severity: 'HIGH',
          category: 'dynamic',
          path: testPath,
          message: `The preflight OPTIONS response reflects untrusted origin '${MALICIOUS_ORIGIN}'.`,
          remediation: 'Validate origin during CORS preflight and reject untrusted domains.',
        });
      }
    } catch {
      // Continue gracefully
    }

    return findings;
  },
};
