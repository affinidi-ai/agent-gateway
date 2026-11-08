// The browser half of an authorization code flow, without a browser: follow
// the redirects from the authorization URL through Hydra and the demo login
// form, keeping Hydra's CSRF cookies, until Hydra sends the user agent back to
// the client's redirect URI.

// A browser's cookie jar, reduced to what Hydra's CSRF cookies need.
class Cookies {
  #byHost = new Map();

  store(url, response) {
    const host = new URL(url).host;
    const jar = this.#byHost.get(host) ?? new Map();
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(';');
      const index = pair.indexOf('=');
      jar.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
    }
    this.#byHost.set(host, jar);
  }

  header(url) {
    const jar = this.#byHost.get(new URL(url).host);
    return jar ? [...jar].map(([name, value]) => `${name}=${value}`).join('; ') : '';
  }
}

/**
 * Signs in as `subject` at the login form and returns the query of the
 * redirect back to `redirectUri` (`code` and `state`, or `error`).
 */
export async function signIn(authorizationUrl, redirectUri, subject, timeout = 20000) {
  const cookies = new Cookies();
  let url = authorizationUrl.toString();
  let init = {};
  for (let hop = 0; hop < 15; hop += 1) {
    const response = await fetch(url, {
      ...init,
      headers: { ...(init.headers ?? {}), cookie: cookies.header(url) },
      redirect: 'manual',
      signal: AbortSignal.timeout(timeout),
    });
    cookies.store(url, response);
    init = {};
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      const next = new URL(response.headers.get('location'), url);
      if (next.toString().startsWith(redirectUri)) {
        return next.searchParams;
      }
      url = next.toString();
      continue;
    }
    const page = new URL(url);
    await response.body?.cancel();
    if (response.status === 200 && page.pathname === '/login') {
      init = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ login_challenge: page.searchParams.get('login_challenge'), subject }).toString(),
      };
      url = `${page.origin}/login`;
      continue;
    }
    throw new Error(`unexpected HTTP ${response.status} from ${page.origin}${page.pathname}`);
  }
  throw new Error('too many redirects while signing in');
}
