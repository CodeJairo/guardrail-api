import type { AxiosInstance, AxiosResponse } from 'axios';
import type { OpenAPIV2, OpenAPIV3, OpenAPIV3_1 } from 'openapi-types';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const SEVERITY_LEVELS: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: 'static' | 'dynamic';
  path?: string;
  method?: string;
  message: string;
  remediation: string;
  details?: Record<string, unknown>;
}

export type AnyOpenAPISpec =
  | OpenAPIV2.Document
  | OpenAPIV3.Document
  | OpenAPIV3_1.Document;

export interface NormalizedSecurityRequirement {
  name: string;
  scopes: string[];
}

export interface NormalizedParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie' | 'formData' | 'body';
  required?: boolean;
  type?: string;
  schema?: any;
  description?: string;
}

export interface NormalizedOperation {
  path: string;
  method: 'get' | 'post' | 'put' | 'delete' | 'patch' | 'options' | 'head';
  operationId?: string;
  summary?: string;
  description?: string;
  security?: NormalizedSecurityRequirement[];
  parameters: NormalizedParameter[];
  requestBody?: {
    required?: boolean;
    schema?: any;
    contentType?: string;
  };
  responses?: Record<string, any>;
  rawOperation: any;
}

export interface NormalizedApiSpec {
  raw: AnyOpenAPISpec;
  dereferenced: AnyOpenAPISpec;
  version: '2.0' | '3.0' | '3.1';
  title: string;
  description?: string;
  servers: string[];
  globalSecurity: NormalizedSecurityRequirement[];
  securitySchemes: Record<string, any>;
  operations: NormalizedOperation[];
}

export interface StaticContext {
  spec: NormalizedApiSpec;
  specPath: string;
}

export interface DynamicHttpClient {
  axios: AxiosInstance;
  baseUrl: string;
  request<T = any>(config: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    params?: Record<string, any>;
    data?: any;
    validateStatus?: (status: number) => boolean;
    timeout?: number;
  }): Promise<AxiosResponse<T>>;
}

export interface DynamicContext {
  spec: NormalizedApiSpec;
  targetUrl: string;
  client: DynamicHttpClient;
  customHeaders?: Record<string, string>;
  timeout?: number;
}

export interface StaticRule {
  id: string;
  name: string;
  description: string;
  defaultSeverity: Severity;
  run(context: StaticContext): Promise<Finding[]> | Finding[];
}

export interface DynamicRule {
  id: string;
  name: string;
  description: string;
  defaultSeverity: Severity;
  run(context: DynamicContext): Promise<Finding[]> | Finding[];
}
