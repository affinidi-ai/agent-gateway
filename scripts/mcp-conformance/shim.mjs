// Upstream adapter between the gateway and the pinned reference server.
//
// The reference server's `subscriptions/listen` response deviates from the
// specification in two ways the gateway rightly refuses:
//
// - It is newline-delimited JSON under `application/json`. Streamable HTTP
//   carries a multi-message response as `text/event-stream`, and the gateway
//   accepts a listen stream from its upstream only as SSE.
// - It tags messages with the request id as a string (`"7"` for id `7`).
//   `io.modelcontextprotocol/subscriptionId` is a `RequestId` equal to the
//   request's id, and the gateway compares it with its type.
//
// This adapter re-frames that one response as SSE, one `message` event per
// line, and restores the tag to the request's typed id, so the suite's
// subscription checks reach the gateway. Every other request and response
// passes through unchanged.
import http from 'node:http';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

const SUBSCRIPTION_ID = 'io.modelcontextprotocol/subscriptionId';

// The id of a `subscriptions/listen` request, or undefined for anything else.
function listenId(body) {
  try {
    const request = JSON.parse(body);
    return request?.method === 'subscriptions/listen' ? request.id : undefined;
  } catch {
    return undefined;
  }
}

// Restores a stringified subscription tag to the request's typed id.
function retag(line, id) {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return line;
  }
  for (const meta of [message?.params?._meta, message?.result?._meta]) {
    if (meta && SUBSCRIPTION_ID in meta && meta[SUBSCRIPTION_ID] !== id && String(meta[SUBSCRIPTION_ID]) === String(id)) {
      meta[SUBSCRIPTION_ID] = id;
    }
  }
  return JSON.stringify(message);
}

function reframe(upstream, res, id) {
  const headers = { ...upstream.headers, 'content-type': 'text/event-stream' };
  delete headers['content-length'];
  res.writeHead(upstream.statusCode, headers);
  let pending = '';
  const flush = (final) => {
    const lines = pending.split('\n');
    pending = final ? '' : lines.pop();
    for (const line of lines) {
      if (line.trim()) {
        res.write(`event: message\ndata: ${retag(line.trim(), id)}\n\n`);
      }
    }
  };
  upstream.setEncoding('utf8');
  upstream.on('data', (chunk) => {
    pending += chunk;
    flush(false);
  });
  upstream.on('end', () => {
    flush(true);
    res.end();
  });
}

function serve(port, target) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, target);
      const proxied = http.request(
        url,
        { method: req.method, headers: { ...req.headers, host: url.host } },
        (upstream) => {
          const json = (upstream.headers['content-type'] ?? '').startsWith('application/json');
          const id = listenId(body.toString('utf8'));
          if (json && id !== undefined) {
            reframe(upstream, res, id);
            return;
          }
          res.writeHead(upstream.statusCode, upstream.headers);
          upstream.pipe(res);
        },
      );
      proxied.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        }
        res.end('upstream unavailable');
      });
      // A caller that goes away cancels the upstream request too.
      res.on('close', () => proxied.destroy());
      proxied.end(body);
    });
  });
  server.listen(port, '127.0.0.1', () => {
    console.log(`upstream shim listening on http://127.0.0.1:${port} -> ${target}`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { port: { type: 'string' }, upstream: { type: 'string' } } });
  const port = Number(values.port);
  if (!Number.isInteger(port) || port <= 0 || !values.upstream) {
    console.error('usage: node shim.mjs --port <port> --upstream <url>');
    process.exit(2);
  }
  serve(port, values.upstream);
}
