import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { parseAndNormalizeSpec } from '../../src/parser/index.js';
import { missingAuthRule } from '../../src/rules/static/missing-auth.js';
import { strictValidationRule } from '../../src/rules/static/strict-validation.js';
import { unprotectedEndpointsRule } from '../../src/rules/static/unprotected-endpoints.js';

describe('Static Security Rules', () => {
  it('ST-001: should flag operations without security schemes', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');
    const spec = await parseAndNormalizeSpec(fixturePath);
    const findings = await missingAuthRule.run({ spec, specPath: fixturePath });

    // In petstore-vulnerable:
    // GET /pets has no security
    // GET /pets/{id} has no security
    // GET /admin/users has no security
    // DELETE /admin/users has no security
    expect(findings.length).toBeGreaterThan(0);
    const unauthenticatedPaths = findings.map((f) => f.path);
    expect(unauthenticatedPaths).toContain('/pets');
    expect(unauthenticatedPaths).toContain('/admin/users');
  });

  it('ST-002: should detect missing type constraints and potential mass assignment', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');
    const spec = await parseAndNormalizeSpec(fixturePath);
    const findings = await strictValidationRule.run({ spec, specPath: fixturePath });

    // /pets query param limit has no type
    const untypedParamFinding = findings.find((f) => f.ruleId === 'ST-002' && f.details?.parameter === 'limit');
    expect(untypedParamFinding).toBeDefined();

    // Pet schema in request body has additionalProperties undefined (mass assignment risk)
    const massAssignment = findings.find((f) => f.title.includes('Mass Assignment'));
    expect(massAssignment).toBeDefined();
  });

  it('ST-003: should flag sensitive endpoints (/admin/users) exposed without auth', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');
    const spec = await parseAndNormalizeSpec(fixturePath);
    const findings = await unprotectedEndpointsRule.run({ spec, specPath: fixturePath });

    const adminFinding = findings.find(
      (f) => f.ruleId === 'ST-003' && f.path === '/admin/users' && f.severity === 'CRITICAL'
    );
    expect(adminFinding).toBeDefined();
    expect(adminFinding?.message).toContain('admin');
  });
});
