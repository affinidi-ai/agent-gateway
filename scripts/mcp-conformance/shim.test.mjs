import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';

import { listenId, reframe, retag } from './shim.mjs';

const SUBSCRIPTION_ID = 'io.modelcontextprotocol/subscriptionId';

function fakeResponse() {
  let ended;
  const res = {
    status: undefined,
    headers: undefined,
    body: '',
    ended: new Promise((resolve) => {
      ended = resolve;
    }),
    writeHead(status, headers) {
      res.status = status;
      res.headers = headers;
    },
    write(chunk) {
      res.body += chunk;
    },
    end() {
      ended();
    },
  };
  return res;
}

function fakeUpstream(headers) {
  const upstream = new PassThrough();
  upstream.statusCode = 200;
  upstream.headers = headers;
  return upstream;
}

test('listenId returns the typed id of a subscriptions/listen request', () => {
  assert.equal(listenId(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'subscriptions/listen' })), 7);
  assert.equal(listenId(JSON.stringify({ jsonrpc: '2.0', id: 'alpha', method: 'subscriptions/listen' })), 'alpha');
});

test('listenId ignores other methods and bodies that are not a JSON request', () => {
  assert.equal(listenId(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list' })), undefined);
  assert.equal(listenId('{"jsonrpc":'), undefined);
  assert.equal(listenId(''), undefined);
  assert.equal(listenId('null'), undefined);
});

test('retag restores a stringified subscription id in params and result metadata', () => {
  const notification = { jsonrpc: '2.0', method: 'notifications/resources/updated', params: { _meta: { [SUBSCRIPTION_ID]: '7' } } };
  const result = { jsonrpc: '2.0', id: 7, result: { _meta: { [SUBSCRIPTION_ID]: '7' } } };

  assert.deepEqual(JSON.parse(retag(JSON.stringify(notification), 7)).params._meta[SUBSCRIPTION_ID], 7);
  assert.deepEqual(JSON.parse(retag(JSON.stringify(result), 7)).result._meta[SUBSCRIPTION_ID], 7);
});

test('retag leaves a different subscription id, untagged messages and non-JSON lines unchanged', () => {
  const other = { jsonrpc: '2.0', method: 'n', params: { _meta: { [SUBSCRIPTION_ID]: '8' } } };
  const untagged = { jsonrpc: '2.0', id: 7, result: {} };

  assert.equal(JSON.parse(retag(JSON.stringify(other), 7)).params._meta[SUBSCRIPTION_ID], '8');
  assert.deepEqual(JSON.parse(retag(JSON.stringify(untagged), 7)), untagged);
  assert.equal(retag('not json', 7), 'not json');
});

test('reframe sends each non-blank line as an SSE message event, split across chunks', async () => {
  const upstream = fakeUpstream({ 'content-type': 'application/json', 'content-length': '120', 'x-upstream': 'kept' });
  const res = fakeResponse();
  const tagged = { jsonrpc: '2.0', method: 'n', params: { _meta: { [SUBSCRIPTION_ID]: '7' } } };
  const final = { jsonrpc: '2.0', id: 7, result: {} };

  reframe(upstream, res, 7);
  upstream.write(`${JSON.stringify(tagged)}\n\n${JSON.stringify(final).slice(0, 10)}`);
  upstream.end(JSON.stringify(final).slice(10));
  await res.ended;

  assert.equal(res.status, 200);
  assert.deepEqual(res.headers, { 'content-type': 'text/event-stream', 'x-upstream': 'kept' });
  const retagged = { ...tagged, params: { _meta: { [SUBSCRIPTION_ID]: 7 } } };
  assert.equal(
    res.body,
    `event: message\ndata: ${JSON.stringify(retagged)}\n\nevent: message\ndata: ${JSON.stringify(final)}\n\n`,
  );
});

test('reframe ends an empty upstream response without events', async () => {
  const upstream = fakeUpstream({ 'content-type': 'application/json' });
  const res = fakeResponse();

  reframe(upstream, res, 7);
  upstream.end();
  await res.ended;

  assert.equal(res.body, '');
});
