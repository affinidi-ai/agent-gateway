// Adapter between the suite's reference client and the gateway.
//
// The reference client sends `MCP-Protocol-Version` but not the `Mcp-Method`
// and `Mcp-Name` standard headers. A server that reads the body must reject a
// request whose standard headers are missing, and the gateway does (HTTP 400,
// -32020). This adapter adds the two headers when a request lacks them, taking
// their values from the body, so the client scenarios reach the gateway. A
// header the client did send passes through unchanged, as does every response.
//
// Some reference-client requests also leave `Accept` to the runtime default
// `*/*`, which the gateway answers with 406: a Streamable HTTP POST lists both
// `application/json` and `text/event-stream`. The adapter sends that list in
// place of a missing or wildcard `Accept`.
import http from 'node:http';

const STREAMABLE_ACCEPT = 'application/json, text/event-stream';

const NAME_PARAM = { 'tools/call': 'name', 'prompts/get': 'name', 'resources/read': 'uri' };
const PLAIN_VALUE = /^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/;

export function encodeHeaderValue(value) {
  return PLAIN_VALUE.test(value) ? value : `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

// The standard headers a request body calls for, or {} when it is not a single
// JSON-RPC request.
export function standardHeaders(body) {
  let message;
  try {
    message = JSON.parse(body);
  } catch {
    return {};
  }
  if (!message || Array.isArray(message) || typeof message.method !== 'string') return {};
  const headers = { 'mcp-method': message.method };
  const name = message.params?.[NAME_PARAM[message.method]];
  if (typeof name === 'string') headers['mcp-name'] = encodeHeaderValue(name);
  return headers;
}

// Only a request that names its revision in `MCP-Protocol-Version` is changed:
// one without it is a legacy request and must reach the gateway as sent.
export function withStandardHeaders(headers, body) {
  if (headers['mcp-protocol-version'] === undefined) return headers;
  const merged = { ...headers };
  for (const [name, value] of Object.entries(standardHeaders(body))) {
    if (merged[name] === undefined) merged[name] = value;
  }
  if (merged.accept === undefined || merged.accept === '*/*') merged.accept = STREAMABLE_ACCEPT;
  return merged;
}

// Starts the adapter on a free loopback port and resolves to { url, close }.
export function startClientShim(gatewayUrl) {
  const upstream = new URL(gatewayUrl);
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const headers = withStandardHeaders(req.headers, body.toString('utf8'));
      headers.host = upstream.host;
      const forward = http.request(
        { host: upstream.hostname, port: upstream.port, path: upstream.pathname, method: req.method, headers },
        (reply) => {
          res.writeHead(reply.statusCode, reply.headers);
          reply.pipe(res);
        },
      );
      forward.on('error', (error) => {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end(`client-shim: ${error.message}`);
      });
      forward.end(body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}${upstream.pathname}`,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}
