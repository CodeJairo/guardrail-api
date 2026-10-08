import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { runAudit, shouldFailAudit } from '../../src/engine/runner.js';
import { generateJsonReport } from '../../src/reporter/json.js';
import { generateMarkdownReport } from '../../src/reporter/markdown.js';
import { generateHtmlReport } from '../../src/reporter/html.js';
import { startMockServer, type MockServerInstance } from '../mock-server.js';

describe('Audit Runner & Multi-format Reporters', () => {
  let mockServer: MockServerInstance;
  const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');

  beforeAll(async () => {
    mockServer = await startMockServer(4060);
  });

  afterAll(async () => {
    await mockServer.close();
  });

  it('should run both static and dynamic checks end-to-end', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      targetUrl: mockServer.baseUrl,
    });

    expect(report.specTitle).toBe('Vulnerable Demo Petstore API');
    expect(report.totalOperations).toBe(6);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.summary.high).toBeGreaterThan(0);

    // Fail threshold calculation
    expect(shouldFailAudit(report.summary, 'CRITICAL')).toBe(true);
    expect(shouldFailAudit(report.summary, 'HIGH')).toBe(true);
    expect(shouldFailAudit({ critical: 0, high: 0, medium: 1, low: 0, info: 0, total: 1 }, 'CRITICAL')).toBe(false);
  });

  it('should run static-only audit when requested', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });

    const hasDynamicFindings = report.findings.some((f) => f.category === 'dynamic');
    expect(hasDynamicFindings).toBe(false);
  });

  it('should generate valid JSON report', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });

    const jsonStr = generateJsonReport(report);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.specTitle).toBe('Vulnerable Demo Petstore API');
    expect(parsed.findings).toBeInstanceOf(Array);
  });

  it('should generate well-structured Markdown report', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });

    const markdown = generateMarkdownReport(report);
    expect(markdown).toContain('# 🛡️ Guardrail API Security Audit Report');
    expect(markdown).toContain('## Summary of Findings');
    expect(markdown).toContain('🔴 **CRITICAL**');
  });

  it('should generate self-contained HTML report with CSS styles', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });

    const html = generateHtmlReport(report);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Guardrail API Security Report');
    expect(html).toContain('<style>');
    expect(html).toContain('class="metric-card"');
  });
});
