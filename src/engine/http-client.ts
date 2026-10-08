import axios, { type AxiosInstance, type AxiosResponse } from 'axios';
import type { DynamicHttpClient } from '../rules/types.js';

export interface CreateHttpClientOptions {
  baseUrl: string;
  timeout?: number;
  customHeaders?: Record<string, string>;
}

export function createHttpClient(options: CreateHttpClientOptions): DynamicHttpClient {
  const { baseUrl, timeout = 5000, customHeaders = {} } = options;

  const instance: AxiosInstance = axios.create({
    baseURL: baseUrl.replace(/\/+$/, ''),
    timeout,
    headers: {
      'User-Agent': 'Guardrail-API-Security-Scanner/1.0',
      ...customHeaders,
    },
    validateStatus: () => true, // capture all status codes (including 4xx and 5xx)
  });

  return {
    axios: instance,
    baseUrl: baseUrl.replace(/\/+$/, ''),
    async request<T = any>(config: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      params?: Record<string, any>;
      data?: any;
      validateStatus?: (status: number) => boolean;
      timeout?: number;
    }): Promise<AxiosResponse<T>> {
      return instance.request<T>({
        ...config,
        headers: {
          ...config.headers,
        },
      });
    },
  };
}

/**
 * Replaces OpenAPI path templates such as /pets/{id} with sample or fuzzed values
 */
export function buildEndpointUrl(
  pathTemplate: string,
  pathParamReplacements: Record<string, string> = {}
): string {
  return pathTemplate.replace(/\{([a-zA-Z0-9_-]+)\}/g, (_, paramName) => {
    if (paramName in pathParamReplacements) {
      return encodeURIComponent(pathParamReplacements[paramName]);
    }
    // Default safe dummy value
    return '1';
  });
}
