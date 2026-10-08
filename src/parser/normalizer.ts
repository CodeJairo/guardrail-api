import type {
  AnyOpenAPISpec,
  NormalizedApiSpec,
  NormalizedOperation,
  NormalizedParameter,
  NormalizedSecurityRequirement,
} from '../rules/types.js';

export function normalizeSpec(
  rawSpec: AnyOpenAPISpec,
  dereferencedSpec: AnyOpenAPISpec
): NormalizedApiSpec {
  const spec = dereferencedSpec as any;

  // Determine specification version
  let version: '2.0' | '3.0' | '3.1' = '3.0';
  if (spec.swagger && spec.swagger.startsWith('2.')) {
    version = '2.0';
  } else if (spec.openapi && spec.openapi.startsWith('3.1')) {
    version = '3.1';
  } else if (spec.openapi && spec.openapi.startsWith('3.0')) {
    version = '3.0';
  }

  const title = spec.info?.title || 'API Specification';
  const description = spec.info?.description;

  // Extract servers / base URLs
  const servers: string[] = [];
  if (version === '2.0') {
    const host = spec.host || 'localhost';
    const basePath = spec.basePath || '';
    const schemes = spec.schemes?.length ? spec.schemes : ['http'];
    for (const scheme of schemes) {
      servers.push(`${scheme}://${host}${basePath}`);
    }
  } else if (Array.isArray(spec.servers)) {
    for (const s of spec.servers) {
      if (s.url) servers.push(s.url);
    }
  }

  // Extract security schemes definitions
  let securitySchemes: Record<string, any> = {};
  if (version === '2.0') {
    securitySchemes = spec.securityDefinitions || {};
  } else {
    securitySchemes = spec.components?.securitySchemes || {};
  }

  // Extract global security requirements
  const globalSecurity: NormalizedSecurityRequirement[] = [];
  if (Array.isArray(spec.security)) {
    for (const secReq of spec.security) {
      for (const [name, scopes] of Object.entries(secReq)) {
        globalSecurity.push({
          name,
          scopes: Array.isArray(scopes) ? (scopes as string[]) : [],
        });
      }
    }
  }

  // Extract all operations
  const operations: NormalizedOperation[] = [];
  const paths = spec.paths || {};
  const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'] as const;

  for (const [pathStr, pathItemObj] of Object.entries<any>(paths)) {
    if (!pathItemObj || typeof pathItemObj !== 'object') continue;

    const pathLevelParams: any[] = Array.isArray(pathItemObj.parameters)
      ? pathItemObj.parameters
      : [];

    for (const method of httpMethods) {
      const op = pathItemObj[method];
      if (!op || typeof op !== 'object') continue;

      // Extract operation-level security or fallback to global security
      let opSecurity: NormalizedSecurityRequirement[] | undefined;
      if (Array.isArray(op.security)) {
        opSecurity = [];
        for (const secReq of op.security) {
          for (const [name, scopes] of Object.entries(secReq)) {
            opSecurity.push({
              name,
              scopes: Array.isArray(scopes) ? (scopes as string[]) : [],
            });
          }
        }
      } else if (globalSecurity.length > 0) {
        opSecurity = [...globalSecurity];
      }

      // Combine and normalize parameters
      const combinedParams = [...pathLevelParams, ...(Array.isArray(op.parameters) ? op.parameters : [])];
      const normalizedParams: NormalizedParameter[] = [];
      let requestBody: NormalizedOperation['requestBody'];

      for (const p of combinedParams) {
        if (!p || typeof p !== 'object') continue;

        // In Swagger 2.0, body parameters are specified in `parameters` with `in: body`
        if (p.in === 'body') {
          requestBody = {
            required: Boolean(p.required),
            schema: p.schema,
            contentType: 'application/json',
          };
          continue;
        }

        normalizedParams.push({
          name: p.name,
          in: p.in,
          required: Boolean(p.required),
          type: p.schema?.type || p.type,
          schema: p.schema || (p.type ? { type: p.type, format: p.format } : undefined),
          description: p.description,
        });
      }

      // In OpenAPI 3.x, requestBody is a dedicated property
      if (!requestBody && op.requestBody) {
        const content = op.requestBody.content || {};
        const jsonContent = content['application/json'] || Object.values(content)[0];
        requestBody = {
          required: Boolean(op.requestBody.required),
          schema: (jsonContent as any)?.schema,
          contentType: content['application/json'] ? 'application/json' : Object.keys(content)[0],
        };
      }

      operations.push({
        path: pathStr,
        method,
        operationId: op.operationId,
        summary: op.summary,
        description: op.description,
        security: opSecurity,
        parameters: normalizedParams,
        requestBody,
        responses: op.responses,
        rawOperation: op,
      });
    }
  }

  return {
    raw: rawSpec,
    dereferenced: dereferencedSpec,
    version,
    title,
    description,
    servers,
    globalSecurity,
    securitySchemes,
    operations,
  };
}
