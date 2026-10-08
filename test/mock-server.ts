import http from 'node:http';

export interface MockServerInstance {
  server: http.Server;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

export function startMockServer(port = 4000): Promise<MockServerInstance> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://localhost:${port}`);
      const origin = req.headers['origin'];

      // Simulate CORS misconfiguration (blind reflection + credentials)
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }

      // Information disclosure headers
      res.setHeader('X-Powered-By', 'Express');
      res.setHeader('Server', 'VulnerableDemo/1.0.0');

      // Intentionally omit X-Content-Type-Options, HSTS, CSP

      // Handle OPTIONS preflight
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      // Route: /api/v1/pets/:id or /pets/:id (fuzzing test: crash with 500 on invalid input)
      if (url.pathname.includes('/pets/fuzz_not_a_number_string')) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Crash: NumberFormatException uncaught' }));
        return;
      }

      // Route: /api/v1/secure/profile or /secure/profile
      // Vulnerable: marked as requiring bearerAuth in OpenAPI, but returns 200 OK without token
      if (url.pathname.includes('/secure/profile')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ user: 'admin', secret: '12345' }));
        return;
      }

      // Route: /api/v1/pets POST
      // Vulnerable: returns 201 without checking auth token
      if (url.pathname.includes('/pets') && req.method === 'POST') {
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 1, name: 'Fido' }));
        return;
      }

      // Default 200 for other endpoints
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', path: url.pathname }));
    });

    server.on('error', reject);

    server.listen(port, () => {
      resolve({
        server,
        port,
        baseUrl: `http://localhost:${port}`,
        close: () =>
          new Promise<void>((resClose) => {
            server.close(() => resClose());
          }),
      });
    });
  });
}
