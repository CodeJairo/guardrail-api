import { parseAndNormalizeSpec } from '../parser/index.js';
import { createHttpClient } from './http-client.js';
import { getDynamicRules, getStaticRules } from '../rules/registry.js';
import type { Finding, Severity } from '../rules/types.js';
import type { GuardrailConfig } from '../config/loader.js';

export interface AuditOptions {
  specPathOrUrl: string;
  targetUrl?: string;
  staticOnly?: boolean;
  dynamicOnly?: boolean;
  timeout?: number;
  customHeaders?: Record<string, string>;
  config?: GuardrailConfig;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface AuditReport {
  specTitle: string;
  specVersion: string;
  specSource: string;
  targetUrl?: string;
  startTime: string;
  endTime: string;
  durationMs: number;
  totalOperations: number;
  findings: Finding[];
  summary: AuditSummary;
}

export async function runAudit(options: AuditOptions): Promise<AuditReport> {
  const startTime = Date.now();
  const startDate = new Date().toISOString();

  // 1. Parse and normalize specification
  const spec = await parseAndNormalizeSpec(options.specPathOrUrl);

  const findings: Finding[] = [];

  // 2. Static Analysis
  if (!options.dynamicOnly) {
    const staticRules = getStaticRules();
    for (const rule of staticRules) {
      try {
        const ruleFindings = await rule.run({
          spec,
          specPath: options.specPathOrUrl,
        });
        findings.push(...ruleFindings);
      } catch (err: any) {
        findings.push({
          ruleId: rule.id,
          title: `Error Executing Static Rule ${rule.name}`,
          severity: 'INFO',
          category: 'static',
          message: `Internal rule execution error: ${err.message || err}`,
          remediation: 'Check specification validity or submit bug report.',
        });
      }
    }
  }

  // 3. Dynamic Analysis
  const mergedHeaders = {
    ...options.config?.customHeaders,
    ...options.customHeaders,
  };
  const effectiveTimeout = options.timeout ?? options.config?.timeout ?? 5000;
  const targetUrl = options.targetUrl ?? options.config?.targetUrl ?? spec.servers[0];

  if (!options.staticOnly && targetUrl) {
    const client = createHttpClient({
      baseUrl: targetUrl,
      timeout: effectiveTimeout,
      customHeaders: mergedHeaders,
    });

    const dynamicRules = getDynamicRules();
    for (const rule of dynamicRules) {
      try {
        const ruleFindings = await rule.run({
          spec,
          targetUrl,
          client,
          customHeaders: mergedHeaders,
          timeout: effectiveTimeout,
        });
        findings.push(...ruleFindings);
      } catch (err: any) {
        findings.push({
          ruleId: rule.id,
          title: `Error Executing Dynamic Rule ${rule.name}`,
          severity: 'INFO',
          category: 'dynamic',
          message: `Network or runtime probe error: ${err.message || err}`,
          remediation: 'Verify API accessibility and target URL configuration.',
        });
      }
    }
  }

  // Filter out findings suppressed by config
  const ignoredRules = new Set(options.config?.ignore?.rules || []);
  const ignoredEndpoints = options.config?.ignore?.endpoints || [];

  const activeFindings = findings.filter((f) => {
    if (ignoredRules.has(f.ruleId)) {
      return false;
    }
    if (f.path && ignoredEndpoints.some((pattern) => f.path === pattern || f.path?.startsWith(pattern))) {
      return false;
    }
    return true;
  });

  // 4. Calculate summary metrics
  const summary: AuditSummary = {
    critical: activeFindings.filter((f) => f.severity === 'CRITICAL').length,
    high: activeFindings.filter((f) => f.severity === 'HIGH').length,
    medium: activeFindings.filter((f) => f.severity === 'MEDIUM').length,
    low: activeFindings.filter((f) => f.severity === 'LOW').length,
    info: activeFindings.filter((f) => f.severity === 'INFO').length,
    total: activeFindings.length,
  };

  const endTime = Date.now();

  return {
    specTitle: spec.title,
    specVersion: spec.version,
    specSource: options.specPathOrUrl,
    targetUrl: !options.staticOnly ? targetUrl : undefined,
    startTime: startDate,
    endTime: new Date().toISOString(),
    durationMs: endTime - startTime,
    totalOperations: spec.operations.length,
    findings: activeFindings,
    summary,
  };
}

export function shouldFailAudit(
  summary: AuditSummary,
  failThreshold: Severity = 'CRITICAL'
): boolean {
  switch (failThreshold) {
    case 'CRITICAL':
      return summary.critical > 0;
    case 'HIGH':
      return summary.critical > 0 || summary.high > 0;
    case 'MEDIUM':
      return summary.critical > 0 || summary.high > 0 || summary.medium > 0;
    case 'LOW':
      return summary.critical > 0 || summary.high > 0 || summary.medium > 0 || summary.low > 0;
    case 'INFO':
      return summary.total > 0;
    default:
      return summary.critical > 0;
  }
}
