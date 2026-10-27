// The MCP server behind the demo surface: Streamable HTTP with JSON answers
// and one `whoami` tool that reports what reached it through the gateway, so
// the demo can show that the caller's token never does.
import http from 'node:http';
import { parseArgs } from 'node:util';

const { values: args } = parseArgs({ options: { port: { type: 'string', default: '18645' } } });
const PORT = Number(args.port);
const MAX_BODY_BYTES = 1024 * 1024;
const VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const TOOLS = [
  {
    name: 'whoami',
    description: 'Report the headers and request metadata that reached this server through the gateway',
    inputSchema: { type: 'object', properties: {} },
  },
];

const result = (id, value) => ({ jsonrpc: '2.0', id, result: value });

function answer(message, headers) {
  switch (message.method) {
    case 'initialize': {
      const requested = message.params?.protocolVersion;
      return result(message.id, {
        protocolVersion: VERSIONS.includes(requested) ? requested : '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'mcp-discovery-demo', version: '1.0.0' },
      });
    }
    case 'ping':
      return result(message.id, {});
    case 'tools/list':
      return result(message.id, { tools: TOOLS });
    case 'tools/call': {
      const seen = {
        authorization_header_received: Object.hasOwn(headers, 'authorization'),
        header_names: Object.keys(headers).sort(),
        meta: message.params?._meta ?? null,
      };
      return result(message.id, { content: [{ type: 'text', text: JSON.stringify(seen, null, 2) }], isError: false });
    }
    default:
      return { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } };
  }
}

http
  .createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
      return;
    }
    if (req.method !== 'POST' || req.url !== '/mcp') {
      res.writeHead(405, { allow: 'POST' }).end();
      return;
    }
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        res.writeHead(413).end();
        return;
      }
      chunks.push(chunk);
    }
    let message;
    try {
      message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
      return;
    }
    if (message.id === undefined) {
      res.writeHead(202).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(answer(message, req.headers)));
  })
  .listen(PORT, '127.0.0.1', () => console.log(`MCP server on http://127.0.0.1:${PORT}/mcp`));
