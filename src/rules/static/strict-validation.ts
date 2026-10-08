import type { Finding, StaticContext, StaticRule } from '../types.js';

export const strictValidationRule: StaticRule = {
  id: 'ST-002',
  name: 'Strict Parameter & Schema Validation',
  description: 'Verifies that input parameters and request bodies enforce strict typing and constraints (length, bounds, regex)',
  defaultSeverity: 'MEDIUM',
  run(context: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const { spec } = context;

    for (const op of spec.operations) {
      const method = op.method.toUpperCase();
      const path = op.path;

      // 1. Check parameters
      for (const param of op.parameters) {
        const schema = param.schema || {};
        const type = param.type || schema.type;

        if (!type) {
          findings.push({
            ruleId: 'ST-002',
            title: 'Untyped Parameter in Operation',
            severity: 'MEDIUM',
            category: 'static',
            path,
            method,
            message: `Parameter '${param.name}' in (${param.in}) does not declare a data type or schema.`,
            remediation: `Define an explicit 'schema.type' (e.g. string, integer, boolean) for parameter '${param.name}'.`,
            details: { parameter: param.name, in: param.in },
          });
          continue;
        }

        if (type === 'string') {
          const hasConstraint = Boolean(
            schema.maxLength !== undefined ||
            schema.pattern !== undefined ||
            schema.enum !== undefined ||
            schema.format !== undefined
          );

          if (!hasConstraint) {
            findings.push({
              ruleId: 'ST-002',
              title: 'Unbounded String Parameter',
              severity: 'LOW',
              category: 'static',
              path,
              method,
              message: `String parameter '${param.name}' in (${param.in}) lacks length or format validation constraints (maxLength, pattern, enum, or format).`,
              remediation: `Add 'maxLength' or 'pattern' constraints to string parameter '${param.name}' to prevent buffer exhaustion and injection payloads.`,
              details: { parameter: param.name, in: param.in },
            });
          }
        } else if (type === 'integer' || type === 'number') {
          const hasBounds = schema.minimum !== undefined || schema.maximum !== undefined;

          if (!hasBounds) {
            findings.push({
              ruleId: 'ST-002',
              title: 'Unbounded Numeric Parameter',
              severity: 'LOW',
              category: 'static',
              path,
              method,
              message: `Numeric parameter '${param.name}' in (${param.in}) does not specify minimum or maximum boundary limits.`,
              remediation: `Define 'minimum' and/or 'maximum' for numeric parameter '${param.name}' to avoid integer overflows or negative value logic bugs.`,
              details: { parameter: param.name, in: param.in },
            });
          }
        }
      }

      // 2. Check requestBody schema
      if (op.requestBody && op.requestBody.schema) {
        const bodySchema = op.requestBody.schema;
        const schemaType = bodySchema.type;

        if (!schemaType && !bodySchema.properties) {
          findings.push({
            ruleId: 'ST-002',
            title: 'Untyped Request Body Schema',
            severity: 'HIGH',
            category: 'static',
            path,
            method,
            message: `Request body for ${method} ${path} lacks explicit object schema or property definitions.`,
            remediation: 'Define an explicit schema with typed properties and validation rules for the request body.',
          });
        }

        if (schemaType === 'object' || bodySchema.properties) {
          // If additionalProperties is true or undefined, it may indicate mass assignment vulnerability
          if (bodySchema.additionalProperties === true || bodySchema.additionalProperties === undefined) {
            findings.push({
              ruleId: 'ST-002',
              title: 'Potential Mass Assignment Vulnerability in Request Body',
              severity: 'MEDIUM',
              category: 'static',
              path,
              method,
              message: `Request body schema for ${method} ${path} does not set 'additionalProperties: false', potentially permitting arbitrary unexpected input fields.`,
              remediation: "Set 'additionalProperties: false' in the request body object schema to prevent mass assignment of sensitive model attributes.",
            });
          }
        }
      }
    }

    return findings;
  },
};
