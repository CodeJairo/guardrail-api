import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { parseAndNormalizeSpec } from '../../src/parser/index.js';
import { startMockServer, type MockServerInstance } from '../mock-server.js';
import { createHttpClient } from '../../src/engine/http-client.js';
import { unauthenticatedProbeRule } from '../../src/rules/dynamic/unauthenticated-probe.js';
import { securityHeadersRule } from '../../src/rules/dynamic/security-headers.js';
import { corsMisconfigRule } from '../../src/rules/dynamic/cors-misconfig.js';
import { payloadFuzzingRule } from '../../src/rules/dynamic/payload-fuzzing.js';

describe('Dynamic Security Rules', () => {
  let mockServer: MockServerInstance;
  let spec: any;

  beforeAll(async () => {
    mockServer = await startMockServer(4050);
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');
    spec = await parseAndNormalizeSpec(fixturePath);
  });

  afterAll(async () => {
    await mockServer.close();
  });

  it('DY-001: should detect unauthenticated access on secured endpoints', async () => {
    const client = createHttpClient({ baseUrl: mockServer.baseUrl });
    const findings = await unauthenticatedProbeRule.run({
      spec,
      targetUrl: mockServer.baseUrl,
      client,
    });

    expect(findings.length).toBeGreaterThan(0);
    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
    expect(criticalFindings.length).toBeGreaterThan(0);

    const profileFinding = findings.find((f) => f.path === '/secure/profile');
    expect(profileFinding).toBeDefined();
    expect(profileFinding?.message).toContain('HTTP 200 OK');
  });

  it('DY-002: should detect missing security headers and info disclosure', async () => {
    const client = createHttpClient({ baseUrl: mockServer.baseUrl });
    const findings = await securityHeadersRule.run({
      spec,
      targetUrl: mockServer.baseUrl,
      client,
    });

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('DY-002');

    const titles = findings.map((f) => f.title);
    expect(titles).toContain('Missing or Invalid X-Content-Type-Options Header');
    expect(titles).toContain('Missing Strict-Transport-Security (HSTS) Header');
    expect(titles).toContain('Information Disclosure via X-Powered-By Header');
  });

  it('DY-003: should detect CORS origin reflection with credentials', async () => {
    const client = createHttpClient({ baseUrl: mockServer.baseUrl });
    const findings = await corsMisconfigRule.run({
      spec,
      targetUrl: mockServer.baseUrl,
      client,
    });

    const corsCritical = findings.find(
      (f) => f.ruleId === 'DY-003' && f.title.includes('Reflection with Credentials')
    );
    expect(corsCritical).toBeDefined();
    expect(corsCritical?.severity).toBe('CRITICAL');
  });

  it('DY-004: should detect unhandled 500 server crash on invalid input', async () => {
    const client = createHttpClient({ baseUrl: mockServer.baseUrl });
    const findings = await payloadFuzzingRule.run({
      spec,
      targetUrl: mockServer.baseUrl,
      client,
    });

    const crashFinding = findings.find(
      (f) => f.ruleId === 'DY-004' && f.title.includes('500 Server Error')
    );
    expect(crashFinding).toBeDefined();
    expect(crashFinding?.path).toBe('/pets/{id}');
  });
});
