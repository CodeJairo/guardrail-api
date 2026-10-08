import { buildEndpointUrl } from '../../engine/http-client.js';
import type { DynamicContext, DynamicRule, Finding } from '../types.js';

export const payloadFuzzingRule: DynamicRule = {
  id: 'DY-004',
  name: 'Input Validation Fuzzing & Error Handling',
  description: 'Fuzzes parameters and request bodies with invalid types and special characters to verify graceful handling (400 Bad Request) instead of internal server errors (500)',
  defaultSeverity: 'HIGH',
  async run(context: DynamicContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { spec, client } = context;

    for (const op of spec.operations) {
      const method = op.method;
      const path = op.path;

      // 1. Fuzz Path Parameters (e.g. expecting integer, send string or injection)
      const pathParams = op.parameters.filter((p) => p.in === 'path');
      if (pathParams.length > 0) {
        for (const p of pathParams) {
          const type = p.type || p.schema?.type;
          // If expected type is integer or number, test invalid string
          const fuzzValue = type === 'integer' || type === 'number'
            ? 'fuzz_not_a_number_string'
            : "fuzz'\"<script>test";

          const fuzzedUrl = buildEndpointUrl(path, { [p.name]: fuzzValue });

          try {
            const res = await client.request({
              method,
              url: fuzzedUrl,
            });

            if (res.status === 500) {
              findings.push({
                ruleId: 'DY-004',
                title: 'Unhandled 500 Server Error on Invalid Path Parameter',
                severity: 'HIGH',
                category: 'dynamic',
                path,
                method: method.toUpperCase(),
                message: `Sending invalid input '${fuzzValue}' for parameter '${p.name}' triggered HTTP 500 Internal Server Error instead of a controlled 400 Bad Request / 422 Unprocessable Entity.`,
                remediation: `Implement input validation middleware on route '${path}' to reject malformed parameters with HTTP 400 Bad Request.`,
                details: { parameter: p.name, value: fuzzValue, statusCode: res.status },
              });
            }
          } catch {
            // Ignore network dropouts
          }
        }
      }

      // 2. Fuzz Query Parameters
      const queryParams = op.parameters.filter((p) => p.in === 'query');
      if (queryParams.length > 0) {
        for (const q of queryParams) {
          const fuzzQuery = { [q.name]: "' OR '1'='1" };
          const targetUrl = buildEndpointUrl(path);

          try {
            const res = await client.request({
              method,
              url: targetUrl,
              params: fuzzQuery,
            });

            if (res.status === 500) {
              findings.push({
                ruleId: 'DY-004',
                title: 'Unhandled 500 Server Error on Fuzzed Query Parameter',
                severity: 'HIGH',
                category: 'dynamic',
                path,
                method: method.toUpperCase(),
                message: `Query parameter '${q.name}' with special characters triggered HTTP 500 Internal Server Error.`,
                remediation: `Sanitize and strictly validate query parameter '${q.name}' to return 400 Bad Request.`,
                details: { queryParam: q.name, statusCode: res.status },
              });
            }
          } catch {
            // Ignore
          }
        }
      }

      // 3. Fuzz Request Body for POST / PUT / PATCH
      if (['post', 'put', 'patch'].includes(method) && op.requestBody) {
        const targetUrl = buildEndpointUrl(path);

        // Send a type-mismatched and malformed payload
        const fuzzedPayload = {
          __unexpected_fuzz_key: '<script>alert(1)</script>',
          id: 'invalid-string-for-id',
          count: 'not-a-number',
        };

        try {
          const res = await client.request({
            method,
            url: targetUrl,
            headers: { 'Content-Type': 'application/json' },
            data: fuzzedPayload,
          });

          if (res.status === 500) {
            findings.push({
              ruleId: 'DY-004',
              title: 'Unhandled 500 Server Error on Malformed JSON Body',
              severity: 'HIGH',
              category: 'dynamic',
              path,
              method: method.toUpperCase(),
              message: `Sending invalid data types in request body to ${method.toUpperCase()} ${path} caused HTTP 500 Internal Server Error.`,
              remediation: 'Use a JSON schema validation library (such as Zod, Joi, or Ajv) to reject invalid request payloads with HTTP 400 Bad Request before processing.',
              details: { statusCode: res.status },
            });
          }
        } catch {
          // Ignore
        }
      }
    }

    return findings;
  },
};
