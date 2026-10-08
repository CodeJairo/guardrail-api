import path from 'node:path';
import fs from 'node:fs';
import SwaggerParser from '@apidevtools/swagger-parser';
import type { AnyOpenAPISpec } from '../rules/types.js';

export interface LoadedSpecResult {
  raw: AnyOpenAPISpec;
  dereferenced: AnyOpenAPISpec;
  sourcePath: string;
}

export async function loadSpecFileOrUrl(inputPathOrUrl: string): Promise<LoadedSpecResult> {
  const isUrl = /^https?:\/\//i.test(inputPathOrUrl);
  let resolvedPath = inputPathOrUrl;

  if (!isUrl) {
    resolvedPath = path.isAbsolute(inputPathOrUrl)
      ? inputPathOrUrl
      : path.resolve(process.cwd(), inputPathOrUrl);

    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`OpenAPI specification file not found at path: ${resolvedPath}`);
    }
  }

  try {
    // Parse raw spec first to preserve raw state
    const rawParsed = (await SwaggerParser.parse(resolvedPath)) as AnyOpenAPISpec;
    
    // Validate and dereference all internal/external $ref pointers
    const dereferenced = (await SwaggerParser.dereference(
      JSON.parse(JSON.stringify(rawParsed))
    )) as AnyOpenAPISpec;

    return {
      raw: rawParsed,
      dereferenced,
      sourcePath: resolvedPath,
    };
  } catch (error: any) {
    throw new Error(`Failed to parse or validate OpenAPI specification (${inputPathOrUrl}): ${error.message || error}`);
  }
}
