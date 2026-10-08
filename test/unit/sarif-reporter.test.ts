import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { runAudit } from '../../src/engine/runner.js';
import { generateSarifReport } from '../../src/reporter/sarif.js';

describe('SARIF 2.1.0 Reporter for GitHub Code Scanning', () => {
  const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');

  it('should generate valid SARIF 2.1.0 JSON matching the specification', async () => {
    const report = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });

    const sarifJson = generateSarifReport(report);
    const parsed = JSON.parse(sarifJson);

    expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeInstanceOf(Array);
    expect(parsed.runs.length).toBe(1);

    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe('guardrail-api');
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);

    // Results mapping
    expect(run.results.length).toBe(report.findings.length);

    const firstResult = run.results[0];
    expect(firstResult.ruleId).toBeDefined();
    expect(['error', 'warning', 'note']).toContain(firstResult.level);
    expect(firstResult.message.text).toBeDefined();
    expect(firstResult.locations[0].physicalLocation.artifactLocation.uri).toBe(fixturePath);
  });
});
