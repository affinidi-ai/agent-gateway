// The official MCP client SDK, the one MCP Inspector is built on, against the
// demo: it finds the authorization server on its own from the 401 challenge,
// and only the browser sign-in is driven here.
import crypto from 'node:crypto';
import { parseArgs } from 'node:util';

import { Client, StreamableHTTPClientTransport, UnauthorizedError } from '@modelcontextprotocol/client';

import { signIn } from './browser.mjs';

const { values: args } = parseArgs({
  options: {
    resource: { type: 'string' },
    'client-id': { type: 'string' },
    'redirect-uri': { type: 'string' },
  },
});
for (const name of ['resource', 'client-id', 'redirect-uri']) {
  if (!args[name]) {
    console.error(`sdk-check.mjs: --${name} is required`);
    process.exit(2);
  }
}
const RESOURCE = new URL(args.resource);
const CLIENT_INFO = { name: 'mcp-discovery-sdk-check', version: '1.0.0' };

let failures = 0;
function report(ok, name, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures += 1;
  return ok;
}

// A pre-registered public client; everything the SDK keeps between the
// redirect and the callback stays in memory.
const saved = {};
const provider = {
  get redirectUrl() {
    return args['redirect-uri'];
  },
  get clientMetadata() {
    return {
      client_name: CLIENT_INFO.name,
      redirect_uris: [args['redirect-uri']],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
  },
  state() {
    saved.state ??= crypto.randomBytes(16).toString('base64url');
    return saved.state;
  },
  clientInformation: () => ({ client_id: args['client-id'] }),
  tokens: () => saved.tokens,
  saveTokens: (tokens) => {
    saved.tokens = tokens;
  },
  redirectToAuthorization: (url) => {
    saved.authorizationUrl = url;
  },
  saveCodeVerifier: (verifier) => {
    saved.verifier = verifier;
  },
  codeVerifier: () => saved.verifier,
  saveDiscoveryState: (state) => {
    saved.discovery = state;
  },
  discoveryState: () => saved.discovery,
};

async function main() {
  const first = new StreamableHTTPClientTransport(RESOURCE, { authProvider: provider });
  try {
    await new Client(CLIENT_INFO).connect(first);
    report(false, 'the SDK is asked to sign in', 'it connected without a token');
    return;
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
  }
  const authorization = saved.authorizationUrl;
  report(
    authorization?.searchParams.get('resource') === RESOURCE.toString(),
    'the SDK found the authorization server from the challenge and asks for a token for the resource',
    authorization ? `${authorization.origin}${authorization.pathname} scope=${authorization.searchParams.get('scope')}` : '(none)',
  );
  const callback = await signIn(authorization, args['redirect-uri'], 'demo-user');
  report(callback.get('state') === saved.state, 'the authorization response carries the state the SDK sent');
  await first.finishAuth(callback);
  const audience = JSON.parse(Buffer.from(saved.tokens.access_token.split('.')[1], 'base64url').toString('utf8')).aud;
  report([audience].flat().includes(RESOURCE.toString()), 'the SDK holds a token issued for the resource', JSON.stringify(audience));

  const transport = new StreamableHTTPClientTransport(RESOURCE, { authProvider: provider });
  const client = new Client(CLIENT_INFO);
  await client.connect(transport);
  report(true, 'the SDK connects with the token', `protocol ${transport.protocolVersion ?? '(not reported)'}`);
  const tools = await client.listTools();
  report(tools.tools.some((tool) => tool.name === 'whoami'), 'the SDK lists the tools through the gateway');
  const call = await client.callTool({ name: 'whoami', arguments: {} });
  const seen = JSON.parse(call.content?.[0]?.text ?? '{}');
  report(seen.authorization_header_received === false, "the caller's token never reaches the MCP server");
  await client.close();
}

try {
  await main();
} catch (error) {
  report(false, 'the SDK flow ran to the end', error.message);
}
console.log(failures === 0 ? 'RESULT: PASS' : `RESULT: FAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);
