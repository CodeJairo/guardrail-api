import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { runAudit } from '../../src/engine/runner.js';
import { loadConfig } from '../../src/config/loader.js';

describe('Config Loader & Finding Suppression', () => {
  const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');

  it('should suppress findings by endpoint path', async () => {
    // Normal run without config has /admin/users critical findings
    const baseReport = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
    });
    const hasAdminBefore = baseReport.findings.some((f) => f.path === '/admin/users');
    expect(hasAdminBefore).toBe(true);

    // Run with ignore endpoint
    const suppressedReport = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
      config: {
        ignore: {
          endpoints: ['/admin/users'],
        },
      },
    });

    const hasAdminAfter = suppressedReport.findings.some((f) => f.path === '/admin/users');
    expect(hasAdminAfter).toBe(false);
    expect(suppressedReport.summary.total).toBeLessThan(baseReport.summary.total);
  });

  it('should suppress findings by rule ID', async () => {
    const reportWithRuleSuppression = await runAudit({
      specPathOrUrl: fixturePath,
      staticOnly: true,
      config: {
        ignore: {
          rules: ['ST-002'],
        },
      },
    });

    const hasSt002 = reportWithRuleSuppression.findings.some((f) => f.ruleId === 'ST-002');
    expect(hasSt002).toBe(false);
  });

  it('should return null when default config does not exist in cwd', () => {
    const config = loadConfig();
    expect(config).toBeNull();
  });

  it('should throw when explicitly provided config path does not exist', () => {
    expect(() => loadConfig('./non-existent-config.json')).toThrow(
      /Configuration file not found/
    );
  });
});
