import fs from 'node:fs';
import path from 'node:path';
import type { Severity } from '../rules/types.js';

export interface GuardrailConfig {
  failOn?: Severity;
  targetUrl?: string;
  timeout?: number;
  customHeaders?: Record<string, string>;
  ignore?: {
    endpoints?: string[];
    rules?: string[];
  };
}

export const DEFAULT_CONFIG_FILENAMES = ['.guardrailrc.json', '.guardrailrc'];

export function loadConfig(explicitPath?: string): GuardrailConfig | null {
  let configPath: string | null = null;

  if (explicitPath) {
    const resolved = path.isAbsolute(explicitPath)
      ? explicitPath
      : path.resolve(process.cwd(), explicitPath);

    if (!fs.existsSync(resolved)) {
      throw new Error(`Configuration file not found at: ${resolved}`);
    }
    configPath = resolved;
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = path.resolve(process.cwd(), filename);
      if (fs.existsSync(candidate)) {
        configPath = candidate;
        break;
      }
    }
  }

  if (!configPath) {
    return null;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(content) as GuardrailConfig;
    return parsed;
  } catch (err: any) {
    throw new Error(`Failed to parse configuration file (${configPath}): ${err.message || err}`);
  }
}
