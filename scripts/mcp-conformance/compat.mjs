// Protocol-era checks the conformance suite does not make.
//
//   probe     a modern request to the Access Point is admitted; exit 2 when the
//             binary answers -32022
//   admitted  every endpoint admits 2026-07-28, including the surface whose
//             record still carries the retired mcp_protocol_mode
//   rejected  every endpoint rejects the unmodelled 2025-11-25 with -32022,
//             a supported list that offers 2024-11-05, and the request id echoed
//   legacy    a 2024-11-05 client session (initialize, notifications/initialized,
//             tools/list, tools/call) gives the same results through the gateway
//             as directly, and owned endpoints return the fixture's text
import fs from 'node:fs';
import { isDeepStrictEqual, parseArgs } from 'node:util';
import { SIMPLE_TEXT } from './fixture.mjs';

const MODERN = '2026-07-28';
const LEGACY = '2024-11-05';
const CLIENT_INFO = { name: 'trust-gateway-compat', version: '1.0.0' };
const UNMODELLED = '2025-11-25';
const ENDPOINTS = ['access-point', 'transit', 'owned-proxy', 'proxy-surface', 'legacy-surface'];
const FORWARDING = ['access-point', 'transit', 'legacy-surface'];
const OWNED = ['owned-proxy', 'proxy-surface'];

const { positionals, values } = parseArgs({ allowPositionals: true, options: { targets: { type: 'string' } } });
const mode = positionals[0];
if (!['probe', 'admitted', 'rejected', 'legacy'].includes(mode) || !values.targets) {
  console.error('usage: node compat.mjs <probe|admitted|rejected|legacy> --targets <targets.json>');
  process.exit(2);
}
const targets = JSON.parse(fs.readFileSync(values.targets, 'utf8'));

let failures = 0;
function report(ok, name, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures += 1;
}

async function readMessage(res, id) {
  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('text/event-stream')) {
    const text = await res.text();
    try {
      return text ? JSON.parse(text) : undefined;
    } catch {
      return { unparsed: text };
    }
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let last;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return last;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      try {
        last = JSON.parse(line.slice(5).trim());
      } catch {
        continue;
      }
      if (last && last.id === id && ('result' in last || 'error' in last)) {
        await reader.cancel().catch(() => {});
        return last;
      }
    }
  }
}

async function post(url, body, headers = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  return { status: res.status, headers: res.headers, message: await readMessage(res, body.id) };
}

function modernToolsList(url, id, version = MODERN) {
  return post(
    url,
    {
      jsonrpc: '2.0',
      id,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': version,
          'io.modelcontextprotocol/clientInfo': CLIENT_INFO,
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    },
    { 'MCP-Protocol-Version': version, 'Mcp-Method': 'tools/list' },
  );
}

function describe(response) {
  return `HTTP ${response.status} ${JSON.stringify(response.message)?.slice(0, 300)}`;
}

function isUnsupported(response, id, requested) {
  const error = response.message?.error;
  const supported = error?.data?.supported;
  return (
    response.status === 400 &&
    response.message?.id === id &&
    error?.code === -32022 &&
    Array.isArray(supported) &&
    supported.includes(LEGACY) &&
    !supported.includes(requested)
  );
}

function isAdmitted(response, id) {
  return response.status === 200 && response.message?.id === id && Array.isArray(response.message?.result?.tools);
}

async function probe() {
  const id = 'compat-probe';
  const response = await modernToolsList(targets['access-point'], id);
  if (response.message?.error?.code === -32022) {
    console.error(`access-point rejected ${MODERN}: the binary does not admit it`);
    process.exit(2);
  }
  report(isAdmitted(response, id), `probe access-point admits ${MODERN}`, describe(response));
}

async function admitted() {
  for (const name of ENDPOINTS) {
    const id = `compat-admitted-${name}`;
    const response = await modernToolsList(targets[name], id);
    report(isAdmitted(response, id), `${name} admits ${MODERN}`, isAdmitted(response, id) ? '' : describe(response));
  }
}

async function rejected() {
  for (const name of ENDPOINTS) {
    const id = `compat-rejected-${name}`;
    const response = await modernToolsList(targets[name], id, UNMODELLED);
    const ok = isUnsupported(response, id, UNMODELLED);
    report(ok, `${name} rejects ${UNMODELLED} with -32022 offering ${LEGACY}`, ok ? '' : describe(response));
  }
}

async function legacySession(url) {
  const call = async (id, method, params, sessionId) => {
    const headers = sessionId ? { 'mcp-session-id': sessionId } : {};
    const response = await post(url, { jsonrpc: '2.0', id, method, params }, headers);
    if (response.status !== 200 || response.message?.id !== id || !('result' in (response.message ?? {}))) {
      throw new Error(`${method}: ${describe(response)}`);
    }
    return response;
  };
  const init = await call(1, 'initialize', { protocolVersion: LEGACY, capabilities: {}, clientInfo: CLIENT_INFO });
  const sessionId = init.headers.get('mcp-session-id') ?? undefined;
  const notified = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    signal: AbortSignal.timeout(20000),
  });
  await notified.body?.cancel();
  if (!notified.ok) {
    throw new Error(`notifications/initialized: HTTP ${notified.status}`);
  }
  const tools = await call(2, 'tools/list', {}, sessionId);
  const result = await call(3, 'tools/call', { name: 'test_simple_text', arguments: {} }, sessionId);
  return {
    initialize: init.message.result,
    toolsList: tools.message.result,
    toolsCall: result.message.result,
  };
}

function firstDifference(a, b, path = '') {
  if (isDeepStrictEqual(a, b)) return undefined;
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const found = firstDifference(a[key], b[key], `${path}/${key}`);
      if (found) return found;
    }
  }
  return `${path || '/'}: ${JSON.stringify(a)?.slice(0, 200)} != ${JSON.stringify(b)?.slice(0, 200)}`;
}

async function sessionOrReport(name) {
  try {
    return await legacySession(targets[name]);
  } catch (error) {
    report(false, `${name} ${LEGACY} session`, error.message);
    return undefined;
  }
}

function toolText(result) {
  return result?.content?.find((item) => item.type === 'text')?.text ?? '';
}

async function legacy() {
  const direct = await sessionOrReport('direct');
  if (direct) {
    report(
      direct.toolsCall?.isError !== true && toolText(direct.toolsCall) === SIMPLE_TEXT,
      `direct ${LEGACY} tools/call returns exactly the text the REST fixture serves`,
      JSON.stringify(direct.toolsCall)?.slice(0, 300),
    );
  }
  for (const name of FORWARDING) {
    const session = await sessionOrReport(name);
    if (direct && session) {
      const difference = firstDifference(session, direct);
      report(!difference, `${name} ${LEGACY} session equals direct`, difference);
    }
  }
  const owned = {};
  for (const name of OWNED) {
    const session = await sessionOrReport(name);
    if (!session) continue;
    owned[name] = session;
    report(
      session.toolsCall?.isError !== true && toolText(session.toolsCall).includes(SIMPLE_TEXT),
      `${name} ${LEGACY} tools/call returns the fixture text`,
      JSON.stringify(session.toolsCall)?.slice(0, 300),
    );
  }
  if (owned['owned-proxy'] && owned['proxy-surface']) {
    const difference = firstDifference(owned['proxy-surface'], owned['owned-proxy']);
    report(!difference, `proxy-surface ${LEGACY} session equals owned-proxy`, difference);
  }
}

await { probe, admitted, rejected, legacy }[mode]();
process.exit(failures === 0 ? 0 : 1);
