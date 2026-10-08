import { Command } from 'commander';
import pc from 'picocolors';
import { runAudit, shouldFailAudit } from '../../engine/runner.js';
import { handleReportOutput, type ReportFormat } from '../../reporter/index.js';
import type { Severity } from '../../rules/types.js';

export function createAuditCommand(): Command {
  return new Command('audit')
    .description('Audit OpenAPI specification and target API for security vulnerabilities')
    .requiredOption('-s, --spec <pathOrUrl>', 'Path or URL to OpenAPI/Swagger specification (JSON or YAML)')
    .option('-t, --target <url>', 'Base URL of running API for dynamic testing')
    .option('--static-only', 'Run only static specification analysis', false)
    .option('--dynamic-only', 'Run only dynamic API security testing', false)
    .option(
      '--fail-on <severity>',
      'Minimum severity level to trigger exit code 1 (critical, high, medium, low, info)',
      'critical'
    )
    .option(
      '-f, --format <format>',
      'Output format (console, json, markdown, html)',
      'console'
    )
    .option('-o, --output <path>', 'Output file path to save report')
    .option('--timeout <ms>', 'Request timeout in milliseconds', '5000')
    .option(
      '-H, --header <headers...>',
      'Custom HTTP headers in Key:Value format (e.g. -H "Authorization: Bearer token")'
    )
    .action(async (options) => {
      try {
        const failThreshold = options.failOn.toUpperCase() as Severity;
        const validSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

        if (!validSeverities.includes(failThreshold)) {
          console.error(
            pc.red(`Error: Invalid --fail-on severity '${options.failOn}'. Must be one of: ${validSeverities.join(', ')}`)
          );
          process.exit(1);
        }

        const validFormats: ReportFormat[] = ['console', 'json', 'markdown', 'html'];
        const format = options.format.toLowerCase() as ReportFormat;
        if (!validFormats.includes(format)) {
          console.error(
            pc.red(`Error: Invalid --format '${options.format}'. Must be one of: ${validFormats.join(', ')}`)
          );
          process.exit(1);
        }

        // Parse custom headers
        const customHeaders: Record<string, string> = {};
        if (Array.isArray(options.header)) {
          for (const h of options.header) {
            const separatorIdx = h.indexOf(':');
            if (separatorIdx > 0) {
              const key = h.slice(0, separatorIdx).trim();
              const val = h.slice(separatorIdx + 1).trim();
              customHeaders[key] = val;
            }
          }
        }

        if (format === 'console' && !options.output) {
          console.log(pc.cyan('🔍 Starting Guardrail API Security Audit...'));
        }

        const report = await runAudit({
          specPathOrUrl: options.spec,
          targetUrl: options.target,
          staticOnly: Boolean(options.staticOnly),
          dynamicOnly: Boolean(options.dynamicOnly),
          timeout: parseInt(options.timeout, 10) || 5000,
          customHeaders,
        });

        const failed = shouldFailAudit(report.summary, failThreshold);

        handleReportOutput(report, {
          format,
          outputPath: options.output,
          failed,
          failThreshold,
        });

        if (failed) {
          process.exit(1);
        }
      } catch (err: any) {
        console.error(pc.red(`\n❌ Fatal Error: ${err.message || err}\n`));
        process.exit(1);
      }
    });
}
