import fs from 'node:fs';
import path from 'node:path';
import type { AuditReport } from '../engine/runner.js';
import type { Severity } from '../rules/types.js';
import { printConsoleReport } from './console.js';
import { generateJsonReport } from './json.js';
import { generateMarkdownReport } from './markdown.js';
import { generateHtmlReport } from './html.js';
import { generateSarifReport } from './sarif.js';

export type ReportFormat = 'console' | 'json' | 'markdown' | 'html' | 'sarif';

export interface ReporterOptions {
  format?: ReportFormat;
  outputPath?: string;
  failed?: boolean;
  failThreshold?: Severity;
}

export function handleReportOutput(
  report: AuditReport,
  options: ReporterOptions = {}
): void {
  const {
    format = 'console',
    outputPath,
    failed = false,
    failThreshold = 'CRITICAL',
  } = options;

  let content: string = '';

  switch (format) {
    case 'json':
      content = generateJsonReport(report);
      break;
    case 'markdown':
      content = generateMarkdownReport(report);
      break;
    case 'html':
      content = generateHtmlReport(report);
      break;
    case 'sarif':
      content = generateSarifReport(report);
      break;
    case 'console':
    default:
      printConsoleReport(report, failed, failThreshold);
      break;
  }

  // If outputPath is provided, save content to disk
  if (outputPath) {
    const resolvedPath = path.isAbsolute(outputPath)
      ? outputPath
      : path.resolve(process.cwd(), outputPath);

    // If format was console but output file was requested, save appropriate format
    let finalContent = content;
    if (format === 'console') {
      if (outputPath.endsWith('.html')) {
        finalContent = generateHtmlReport(report);
      } else if (outputPath.endsWith('.md')) {
        finalContent = generateMarkdownReport(report);
      } else if (outputPath.endsWith('.sarif')) {
        finalContent = generateSarifReport(report);
      } else {
        finalContent = generateJsonReport(report);
      }
    }

    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, finalContent, 'utf-8');
    console.log(`\n📄 Report saved successfully to: ${resolvedPath}`);
  } else if (format !== 'console') {
    // If format is json, markdown, or html, print to stdout
    console.log(content);
  }
}

export * from './console.js';
export * from './json.js';
export * from './markdown.js';
export * from './html.js';
export * from './sarif.js';
