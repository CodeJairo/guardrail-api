import type { DynamicRule, StaticRule } from './types.js';
import { missingAuthRule } from './static/missing-auth.js';
import { strictValidationRule } from './static/strict-validation.js';
import { unprotectedEndpointsRule } from './static/unprotected-endpoints.js';
import { unauthenticatedProbeRule } from './dynamic/unauthenticated-probe.js';
import { securityHeadersRule } from './dynamic/security-headers.js';
import { corsMisconfigRule } from './dynamic/cors-misconfig.js';
import { payloadFuzzingRule } from './dynamic/payload-fuzzing.js';

export const STATIC_RULES: StaticRule[] = [
  missingAuthRule,
  strictValidationRule,
  unprotectedEndpointsRule,
];

export const DYNAMIC_RULES: DynamicRule[] = [
  unauthenticatedProbeRule,
  securityHeadersRule,
  corsMisconfigRule,
  payloadFuzzingRule,
];

export function getStaticRules(): StaticRule[] {
  return [...STATIC_RULES];
}

export function getDynamicRules(): DynamicRule[] {
  return [...DYNAMIC_RULES];
}

export function findRuleById(id: string): StaticRule | DynamicRule | undefined {
  return [...STATIC_RULES, ...DYNAMIC_RULES].find((r) => r.id === id);
}
