import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { encodeHeaderValue, standardHeaders, startClientShim, withStandardHeaders } from './client-shim.mjs';
import { accessPointUrl, killChildrenOnSignal, settings } from './client-driver.mjs';

const request = (method, params) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });

test('a list request gets Mcp-Method only', () => {
  assert.deepEqual(standardHeaders(request('tools/list', {})), { 'mcp-method': 'tools/list' });
});

test('a named request gets Mcp-Name from its name or uri', () => {
  assert.deepEqual(standardHeaders(request('tools/call', { name: 'add_numbers' })), {
    'mcp-method': 'tools/call',
    'mcp-name': 'add_numbers',
  });
  assert.equal(standardHeaders(request('resources/read', { uri: 'test://a' }))['mcp-name'], 'test://a');
  assert.equal(standardHeaders(request('prompts/get', { name: 'p' }))['mcp-name'], 'p');
});

test('a name that is not plain ASCII is Base64 encoded', () => {
  assert.equal(encodeHeaderValue('plain name'), 'plain name');
  assert.equal(encodeHeaderValue('café'), `=?base64?${Buffer.from('café').toString('base64')}?=`);
  assert.equal(encodeHeaderValue(' padded'), `=?base64?${Buffer.from(' padded').toString('base64')}?=`);
});

test('a body that is not one JSON-RPC request gets no headers', () => {
  assert.deepEqual(standardHeaders('not json'), {});
  assert.deepEqual(standardHeaders('[]'), {});
  assert.deepEqual(standardHeaders(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })), {});
  assert.deepEqual(standardHeaders(request('tools/call', { name: 7 })), { 'mcp-method': 'tools/call' });
});

const MODERN = { 'mcp-protocol-version': '2026-07-28' };

test('a header the client sent is kept', () => {
  const merged = withStandardHeaders(
    { ...MODERN, 'mcp-method': 'wrong/method', accept: 'application/json' },
    request('tools/call', { name: 'x' }),
  );
  assert.equal(merged['mcp-method'], 'wrong/method');
  assert.equal(merged['mcp-name'], 'x');
  assert.equal(merged.accept, 'application/json');
});

test('a missing or wildcard Accept becomes the Streamable HTTP list', () => {
  const body = request('tools/list', {});
  assert.equal(withStandardHeaders(MODERN, body).accept, 'application/json, text/event-stream');
  assert.equal(withStandardHeaders({ ...MODERN, accept: '*/*' }, body).accept, 'application/json, text/event-stream');
});

test('a request without MCP-Protocol-Version is not changed', () => {
  const headers = { 'content-type': 'application/json', accept: '*/*' };
  assert.equal(withStandardHeaders(headers, request('tools/call', { name: 'x' })), headers);
});

test('the adapter forwards the request with the added headers and returns the reply', async () => {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      seen.push({ headers: req.headers, body, url: req.url });
      res.writeHead(418, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const shim = await startClientShim(`http://127.0.0.1:${upstream.address().port}/conformance/mcp`);
  try {
    const body = request('tools/call', { name: 'add_numbers' });
    const headers = { 'content-type': 'application/json', 'MCP-Protocol-Version': '2026-07-28' };
    const reply = await fetch(shim.url, { method: 'POST', headers, body });
    assert.equal(reply.status, 418);
    assert.deepEqual(await reply.json(), { ok: true });
    assert.equal(seen[0].url, '/conformance/mcp');
    assert.equal(seen[0].body, body);
    assert.equal(seen[0].headers['mcp-method'], 'tools/call');
    assert.equal(seen[0].headers['mcp-name'], 'add_numbers');
  } finally {
    await shim.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('driver settings need a mode, a reference checkout and the suite URL', () => {
  const env = { MCP_CONFORMANCE_DRIVER_MODE: 'direct', MCP_CONFORMANCE_DRIVER_REFERENCE: '/ref', MCP_CONFORMANCE_DRIVER_LOGS: '/logs' };
  assert.deepEqual(settings(env, ['node', 'driver', 'http://localhost:1/mcp']), {
    mode: 'direct',
    suiteUrl: 'http://localhost:1/mcp',
    referenceDir: '/ref',
    logDir: '/logs',
  });
  assert.throws(() => settings(env, ['node', 'driver']), /server URL/);
  assert.throws(() => settings({ ...env, MCP_CONFORMANCE_DRIVER_MODE: 'other' }, ['n', 'd', 'http://x']), /direct or gateway/);
  assert.throws(
    () => settings({ ...env, MCP_CONFORMANCE_DRIVER_MODE: 'gateway' }, ['n', 'd', 'http://x']),
    /MCP_CONFORMANCE_DRIVER_BINARY is required/,
  );
  assert.equal(accessPointUrl(18790), 'http://127.0.0.1:18790/conformance/mcp');
});

test('a signal to the driver kills the processes it started and no others', () => {
  const target = new EventEmitter();
  const exits = [];
  target.exit = (code) => exits.push(code);
  const killed = [];
  const child = (name) => ({ kill: (signal) => killed.push(`${name}:${signal}`) });
  const running = new Set([child('gateway'), child('client')]);
  killChildrenOnSignal(running, target);
  assert.deepEqual(killed, []);
  target.emit('SIGTERM');
  assert.deepEqual(killed, ['gateway:SIGKILL', 'client:SIGKILL']);
  assert.deepEqual(exits, [1]);
});

test('a driver with nothing running exits on a signal without killing anything', () => {
  const target = new EventEmitter();
  const exits = [];
  target.exit = (code) => exits.push(code);
  killChildrenOnSignal(new Set(), target);
  target.emit('SIGINT');
  assert.deepEqual(exits, [1]);
});

const CANCEL_TIMEOUT_MS = 5_000;

test('a client that disconnects mid-stream closes the forwarded request', async () => {
  let upstreamClosed;
  const closed = new Promise((resolve) => (upstreamClosed = resolve));
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: first\n\n');
    });
    res.on('close', () => upstreamClosed(res.writableFinished));
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const shim = await startClientShim(`http://127.0.0.1:${upstream.address().port}/mcp`);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      upstream.closeAllConnections();
      reject(new Error(`the forwarded request was still open ${CANCEL_TIMEOUT_MS} ms after the client disconnected`));
    }, CANCEL_TIMEOUT_MS);
  });
  try {
    const disconnected = new Promise((resolve) => {
      const client = http.request(shim.url, { method: 'POST', headers: { 'content-type': 'application/json' } }, (reply) => {
        reply.once('data', () => {
          client.destroy();
          resolve();
        });
      });
      client.on('error', () => {});
      client.end(request('tools/list', {}));
    });
    await Promise.race([disconnected, timeout]);
    assert.equal(await Promise.race([closed, timeout]), false);
  } finally {
    clearTimeout(timer);
    await shim.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('an upstream that dies after its headers closes the client response and leaves nothing unhandled', async () => {
  const upstream = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: first\n\n');
      setTimeout(() => res.socket.destroy(), 50);
    });
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const shim = await startClientShim(`http://127.0.0.1:${upstream.address().port}/mcp`);
  const unhandled = [];
  const record = (error) => unhandled.push(error);
  process.on('uncaughtException', record);
  let client;
  try {
    const outcome = await new Promise((resolve) => {
      client = http.request(shim.url, { method: 'POST', headers: { 'content-type': 'application/json' } }, (reply) => {
        reply.on('error', () => resolve('closed'));
        reply.on('close', () => resolve('closed'));
        reply.resume();
      });
      client.on('error', () => resolve('closed'));
      setTimeout(() => resolve('still open'), 2_000).unref();
      client.end(request('tools/list', {}));
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(outcome, 'closed');
    assert.deepEqual(unhandled.map((error) => error.message), []);
  } finally {
    process.off('uncaughtException', record);
    client?.destroy();
    upstream.closeAllConnections();
    await shim.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

async function unusedPort() {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, '127.0.0.1', resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

test('a completed response leaves the shim quiet and a failed forward still answers 502', async () => {
  const errors = [];
  const onError = (error) => errors.push(error);
  process.on('uncaughtException', onError);
  const shim = await startClientShim(`http://127.0.0.1:${await unusedPort()}/mcp`);
  try {
    const reply = await fetch(shim.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: request('tools/list', {}) });
    assert.equal(reply.status, 502);
    assert.match(await reply.text(), /^client-shim: /);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(errors, []);
  } finally {
    process.off('uncaughtException', onError);
    await shim.close();
  }
});
