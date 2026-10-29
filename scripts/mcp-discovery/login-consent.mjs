// Login and consent app for the demo Ory Hydra.
//
// Login shows a one-field form: the name typed becomes the token subject, so a
// person can sign in as different callers. Consent is accepted at once and
// grants the requested scopes plus, as the access token audience, every
// RFC 8707 `resource` the client sent. Hydra ignores `resource` itself, so
// without this step its tokens would not name the MCP server and the gateway
// would refuse them. Hydra still checks each granted audience against the
// client's allowed audiences.
import http from 'node:http';
import { parseArgs } from 'node:util';

const { values: args } = parseArgs({
  options: {
    port: { type: 'string', default: '18644' },
    'hydra-admin': { type: 'string', default: 'https://localhost:4445' },
  },
});
const PORT = Number(args.port);
const ADMIN = args['hydra-admin'].replace(/\/$/, '');
const SUBJECT = /^[A-Za-z0-9._@-]{1,64}$/;
const MAX_FORM_BYTES = 4096;

const escape = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

async function admin(method, path, challengeName, challenge, body) {
  const url = `${ADMIN}/admin/oauth2/auth/requests/${path}?${challengeName}=${encodeURIComponent(challenge)}`;
  const response = await fetch(url, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    throw new Error(`Hydra admin ${method} ${path} answered ${response.status}`);
  }
  return response.json();
}

function send(res, status, headers, body = '') {
  res.writeHead(status, { 'cache-control': 'no-store', ...headers });
  res.end(body);
}

const redirect = (res, location) => send(res, 302, { location });

function loginPage(challenge, error) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Demo authorization server</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}
input,button{font:inherit;padding:.5rem;margin-top:.5rem}input{width:100%;box-sizing:border-box}
.error{color:#b00020}</style></head><body>
<h1>Sign in</h1>
<p>Demo authorization server (Ory Hydra). The name you enter becomes the subject of the access token.</p>
${error ? `<p class="error">${escape(error)}</p>` : ''}
<form method="post" action="/login">
<input type="hidden" name="login_challenge" value="${escape(challenge)}">
<label>Name<input name="subject" value="demo-user" autofocus></label>
<button type="submit">Sign in</button>
</form></body></html>`;
}

async function readForm(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_FORM_BYTES) {
      throw new Error('form too large');
    }
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

async function handle(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/health') {
    return send(res, 200, { 'content-type': 'text/plain' }, 'ok');
  }
  if (req.method === 'GET' && url.pathname === '/login') {
    const challenge = url.searchParams.get('login_challenge') ?? '';
    const login = await admin('GET', 'login', 'login_challenge', challenge);
    if (login.skip) {
      const accepted = await admin('PUT', 'login/accept', 'login_challenge', challenge, { subject: login.subject });
      return redirect(res, accepted.redirect_to);
    }
    return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, loginPage(challenge));
  }
  if (req.method === 'POST' && url.pathname === '/login') {
    const form = await readForm(req);
    const challenge = form.get('login_challenge') ?? '';
    const subject = (form.get('subject') ?? '').trim();
    if (!SUBJECT.test(subject)) {
      return send(res, 400, { 'content-type': 'text/html; charset=utf-8' },
        loginPage(challenge, 'Use 1 to 64 letters, digits, dots, dashes, underscores or @.'));
    }
    const accepted = await admin('PUT', 'login/accept', 'login_challenge', challenge, { subject, remember: false });
    return redirect(res, accepted.redirect_to);
  }
  if (req.method === 'GET' && url.pathname === '/consent') {
    const challenge = url.searchParams.get('consent_challenge') ?? '';
    const consent = await admin('GET', 'consent', 'consent_challenge', challenge);
    const resources = new URL(consent.request_url, ADMIN).searchParams.getAll('resource');
    const audience = [...new Set([...(consent.requested_access_token_audience ?? []), ...resources])];
    const accepted = await admin('PUT', 'consent/accept', 'consent_challenge', challenge, {
      grant_scope: consent.requested_scope ?? [],
      grant_access_token_audience: audience,
      remember: false,
    });
    return redirect(res, accepted.redirect_to);
  }
  return send(res, 404, { 'content-type': 'text/plain' }, 'not found');
}

http
  .createServer((req, res) => {
    handle(req, res).catch((error) => {
      console.error(`login-consent: ${error.message}`);
      send(res, 502, { 'content-type': 'text/plain' }, 'The authorization server refused the request');
    });
  })
  .listen(PORT, '127.0.0.1', () => console.log(`login and consent app on http://localhost:${PORT}`));
