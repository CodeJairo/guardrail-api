import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { parseAndNormalizeSpec } from '../../src/parser/index.js';

describe('OpenAPI Parser & Normalizer', () => {
  it('should parse and normalize a valid OpenAPI JSON spec', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.json');
    const spec = await parseAndNormalizeSpec(fixturePath);

    expect(spec.version).toBe('3.0');
    expect(spec.title).toBe('Vulnerable Demo Petstore API');
    expect(spec.servers).toContain('http://localhost:4000/api/v1');
    expect(spec.securitySchemes).toHaveProperty('bearerAuth');

    // Operations count:
    // /pets GET, POST
    // /pets/{id} GET
    // /admin/users GET, DELETE
    // /secure/profile GET
    expect(spec.operations.length).toBe(6);

    const postPet = spec.operations.find((op) => op.path === '/pets' && op.method === 'post');
    expect(postPet).toBeDefined();
    expect(postPet?.security).toEqual([{ name: 'bearerAuth', scopes: [] }]);
    expect(postPet?.requestBody?.required).toBe(true);
    // Verified dereferencing
    expect(postPet?.requestBody?.schema?.properties?.name?.type).toBe('string');
  });

  it('should parse and normalize a YAML OpenAPI spec', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/petstore-vulnerable.yaml');
    const spec = await parseAndNormalizeSpec(fixturePath);

    expect(spec.version).toBe('3.0');
    expect(spec.title).toBe('Vulnerable Demo Petstore API (YAML)');
    expect(spec.operations.length).toBe(1);
  });

  it('should throw clear error when spec file does not exist', async () => {
    await expect(parseAndNormalizeSpec('./does-not-exist.json')).rejects.toThrow(
      /OpenAPI specification file not found/
    );
  });
});
