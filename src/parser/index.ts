import { loadSpecFileOrUrl } from './loader.js';
import { normalizeSpec } from './normalizer.js';
import type { NormalizedApiSpec } from '../rules/types.js';

export async function parseAndNormalizeSpec(inputPathOrUrl: string): Promise<NormalizedApiSpec> {
  const loaded = await loadSpecFileOrUrl(inputPathOrUrl);
  return normalizeSpec(loaded.raw, loaded.dereferenced);
}

export * from './loader.js';
export * from './normalizer.js';
