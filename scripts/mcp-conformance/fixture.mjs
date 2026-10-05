// REST backend of the gateway-owned MCP Proxy. `GET /simple-text` answers with
// the text the reference server's `test_simple_text` tool returns, so an owned
// `tools/call` can be checked for the real backend body rather than for any
// non-empty text.
import http from 'node:http';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

export const SIMPLE_TEXT = 'This is a simple text response for testing.';

export const OPENAPI_SPEC = `openapi: 3.0.0
info:
  title: MCP conformance fixture
  version: 1.0.0
paths:
  /simple-text:
    get:
      operationId: test_simple_text
      summary: Tests simple text content response
      responses:
        '200':
          description: The reference simple text
          content:
            text/plain:
              schema:
                type: string
`;

function serve(port) {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && new URL(req.url, 'http://fixture').pathname === '/simple-text') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(SIMPLE_TEXT);
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('not found');
  });
  server.listen(port, '127.0.0.1', () => {
    console.log(`REST fixture listening on http://127.0.0.1:${port}`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { port: { type: 'string' } } });
  const port = Number(values.port);
  if (!Number.isInteger(port) || port <= 0) {
    console.error('usage: node fixture.mjs --port <port>');
    process.exit(2);
  }
  serve(port);
}
