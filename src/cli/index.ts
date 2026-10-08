import { Command } from 'commander';
import { createAuditCommand } from './commands/audit.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('guardrail-api')
    .description('Automated API Security Testing CLI: Static OpenAPI Analysis & Dynamic Security Probes')
    .version('1.0.0');

  program.addCommand(createAuditCommand());

  return program;
}

export function runCli(): void {
  const cli = createCli();
  cli.parse(process.argv);
}

// Execute if run directly
const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('guardrail.js') ||
    process.argv[1].endsWith('cli/index.ts') ||
    process.argv[1].endsWith('cli/index.js'));

if (isDirectRun) {
  runCli();
}
