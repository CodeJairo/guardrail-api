import { buildEndpointUrl } from '../../engine/http-client.js';
import type { DynamicContext, DynamicRule, Finding } from '../types.js';

export const securityHeadersRule: DynamicRule = {
  id: 'DY-002',
  name: 'Security Headers Validation',
  description: 'Verifies the presence of recommended HTTP security headers and absence of information leakage headers',
  defaultSeverity: 'MEDIUM',
  async run(context: DynamicContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { spec, client } = context;

    // Pick first available GET operation or fallback to root '/'
    const firstGetOp = spec.operations.find((op) => op.method === 'get');
    const testPath = firstGetOp ? buildEndpointUrl(firstGetOp.path) : '/';

    try {
      const response = await client.request({
        method: 'get',
        url: testPath,
      });

      const headers = response.headers;

      const baseUrlTrimmed = context.targetUrl.replace(/\/+$/, '');
      const testUrl = `${baseUrlTrimmed}${testPath}`;

      // 1. X-Content-Type-Options
      const xcto = headers['x-content-type-options'];
      if (!xcto || String(xcto).toLowerCase() !== 'nosniff') {
        findings.push({
          ruleId: 'DY-002',
          title: 'Missing or Invalid X-Content-Type-Options Header',
          severity: 'MEDIUM',
          category: 'dynamic',
          path: testPath,
          message: "The response is missing 'X-Content-Type-Options: nosniff'. Browsers may attempt MIME-sniffing, leading to XSS vulnerabilities.",
          remediation: "Set 'X-Content-Type-Options: nosniff' header on all HTTP responses.",
          reproduction: `curl -i -X GET "${testUrl}"`,
        });
      }

      // 2. Strict-Transport-Security (HSTS)
      const hsts = headers['strict-transport-security'];
      if (!hsts) {
        findings.push({
          ruleId: 'DY-002',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          severity: 'HIGH',
          category: 'dynamic',
          path: testPath,
          message: "The response is missing 'Strict-Transport-Security'. Connections can be downgraded to unencrypted HTTP via MITM attacks.",
          remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to enforce HTTPS.",
          reproduction: `curl -i -X GET "${testUrl}"`,
        });
      }

      // 3. X-Frame-Options & Content-Security-Policy
      const xfo = headers['x-frame-options'];
      const csp = headers['content-security-policy'];

      if (!xfo && (!csp || !String(csp).includes('frame-ancestors'))) {
        findings.push({
          ruleId: 'DY-002',
          title: 'Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)',
          severity: 'MEDIUM',
          category: 'dynamic',
          path: testPath,
          message: "Neither 'X-Frame-Options' nor 'Content-Security-Policy: frame-ancestors' are present, making the application vulnerable to clickjacking/UI redressing.",
          remediation: "Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none''.",
        });
      }

      if (!csp) {
        findings.push({
          ruleId: 'DY-002',
          title: 'Missing Content-Security-Policy Header',
          severity: 'LOW',
          category: 'dynamic',
          path: testPath,
          message: "Response is missing 'Content-Security-Policy' (CSP) header, which provides defense-in-depth against content injection and XSS.",
          remediation: "Configure a strict 'Content-Security-Policy' header tailored for your API responses.",
        });
      }

      // 4. Information Disclosure Headers (X-Powered-By, Server details)
      const xPoweredBy = headers['x-powered-by'];
      if (xPoweredBy) {
        findings.push({
          ruleId: 'DY-002',
          title: 'Information Disclosure via X-Powered-By Header',
          severity: 'LOW',
          category: 'dynamic',
          path: testPath,
          message: `The server exposes its underlying technology stack via 'X-Powered-By: ${xPoweredBy}'.`,
          remediation: "Disable or remove the 'X-Powered-By' header in your web server / framework configuration.",
          details: { 'X-Powered-By': xPoweredBy },
        });
      }

      const serverHeader = headers['server'];
      if (serverHeader && /\d+\.\d+/.test(String(serverHeader))) {
        findings.push({
          ruleId: 'DY-002',
          title: 'Verbose Server Version Banner Disclosure',
          severity: 'LOW',
          category: 'dynamic',
          path: testPath,
          message: `The server exposes detailed software version information via 'Server: ${serverHeader}', aiding attacker fingerprinting.`,
          remediation: "Configure the server banner to generic output or suppress the 'Server' header entirely.",
          details: { Server: serverHeader },
        });
      }
    } catch {
      // Continue gracefully if server unreachable
    }

    return findings;
  },
};
