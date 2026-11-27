import { waitFor } from '@testing-library/react';

let sessionManager: typeof import('./api').sessionManager;

const fetchMock = jest.fn();
const assign = jest.fn();
const reload = jest.fn();
const originalLocation = window.location;
const PROVIDER_SIGN_OUT = 'https://idp.example.com/logout?id_token_hint=h&state=s';

const response = (body: string, status = 200) =>
  new Response(body, { status, headers: { 'Content-Type': 'application/json' } });

const answer = (body: string, status = 200) => fetchMock.mockResolvedValue(response(body, status));

let addListener: jest.SpyInstance;

beforeEach(() => {
  jest.isolateModules(() => {
    ({ sessionManager } = require('./api'));
  });
  addListener = jest.spyOn(window, 'addEventListener');
  fetchMock.mockReset();
  assign.mockReset();
  reload.mockReset();
  global.fetch = fetchMock;
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...originalLocation, assign, reload, href: '/', pathname: '/', search: '', hash: '' },
  });
  sessionStorage.setItem('session_token', 'tok');
});

afterEach(() => {
  for (const [type, listener] of addListener.mock.calls) window.removeEventListener(type, listener);
  addListener.mockRestore();
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
  sessionStorage.clear();
});

test('logout resolves to the identity provider sign-out address when the gateway gives one', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }));

  await expect(sessionManager.logout()).resolves.toBe(PROVIDER_SIGN_OUT);
  expect(fetchMock).toHaveBeenCalledWith(
    '/api/auth/logout',
    expect.objectContaining({ method: 'POST', headers: { Authorization: 'Bearer tok' } })
  );
  expect(sessionStorage.getItem('session_token')).toBeNull();
  expect(assign).not.toHaveBeenCalled();
});

test.each([
  ['an empty answer', '{}'],
  ['no body', ''],
  ['a body that is not JSON', 'not json'],
  ['a script address', JSON.stringify({ end_session_url: `${'javascript'}:alert(1)` })],
  ['a data address', JSON.stringify({ end_session_url: 'data:text/html,signed out' })],
  ['a relative address', JSON.stringify({ end_session_url: '/logout' })],
  ['a protocol-relative address', JSON.stringify({ end_session_url: '//idp.example/logout' })],
  ['an address that is not a string', JSON.stringify({ end_session_url: 42 })],
])('logout resolves to nothing for %s', async (_case, body) => {
  answer(body);

  await expect(sessionManager.logout()).resolves.toBeUndefined();
  expect(sessionStorage.getItem('session_token')).toBeNull();
});

test('logout resolves to nothing when the gateway refuses or cannot be reached', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }), 500);
  await expect(sessionManager.logout()).resolves.toBeUndefined();

  const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  fetchMock.mockRejectedValue(new Error('offline'));
  await expect(sessionManager.logout()).resolves.toBeUndefined();
  expect(sessionStorage.getItem('session_token')).toBeNull();
  consoleError.mockRestore();
});

test('an explicit sign-out goes to the provider sign-out address', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }));

  await expect(sessionManager.signOut()).resolves.toBe(true);

  expect(assign).toHaveBeenCalledWith(PROVIDER_SIGN_OUT);
});

test.each([
  ['a plain http address', 'http://idp.example/logout', 'http://idp.example/logout'],
  ['an upper-case scheme', 'HTTPS://idp.example/logout', 'https://idp.example/logout'],
  ['a scheme without slashes', 'https:idp.example', 'https://idp.example/'],
])('an explicit sign-out follows the address it checked for %s', async (_case, given, checked) => {
  answer(JSON.stringify({ end_session_url: given }));

  await expect(sessionManager.signOut()).resolves.toBe(true);

  expect(assign).toHaveBeenCalledTimes(1);
  expect(assign).toHaveBeenCalledWith(checked);
});

test('an explicit sign-out without a provider address stays in the dashboard', async () => {
  answer('{}');

  await expect(sessionManager.signOut()).resolves.toBe(false);
  expect(assign).not.toHaveBeenCalled();
});

test.each([
  ['a protocol-relative address', '//idp.example/logout'],
  ['a script address', `${'javascript'}:alert(1)`],
  ['a data address', 'data:text/html,signed out'],
])('an explicit sign-out never follows %s', async (_case, address) => {
  answer(JSON.stringify({ end_session_url: address }));

  await expect(sessionManager.signOut()).resolves.toBe(false);
  expect(assign).not.toHaveBeenCalled();
});

test('an expired session never signs the person out of the identity provider', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }));

  sessionManager.expireSession();

  await waitFor(() => expect(reload).toHaveBeenCalled());
  expect(assign).not.toHaveBeenCalled();
  expect(sessionManager.didSessionExpire()).toBe(true);
});

test('a session expiring while the browser leaves for the provider neither reloads nor reports it', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }));
  await sessionManager.signOut();

  sessionManager.expireSession();

  expect(sessionManager.didSessionExpire()).toBe(false);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(reload).not.toHaveBeenCalled();
});

test('a session that expired just before the browser leaves does not reload over the provider sign-out', async () => {
  let answerExpiredLogout: (answer: Response) => void = () => {};
  fetchMock
    .mockReturnValueOnce(
      new Promise<Response>(resolve => {
        answerExpiredLogout = resolve;
      })
    )
    .mockResolvedValueOnce(response(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT })));

  const logout = jest.spyOn(sessionManager, 'logout');

  sessionManager.expireSession();
  await expect(sessionManager.signOut()).resolves.toBe(true);
  answerExpiredLogout(response('{}'));

  await logout.mock.results[0].value;
  expect(assign).toHaveBeenCalledWith(PROVIDER_SIGN_OUT);
  expect(reload).not.toHaveBeenCalled();
});

test('a page restored from the back-forward cache after leaving for the provider reloads', async () => {
  answer(JSON.stringify({ end_session_url: PROVIDER_SIGN_OUT }));
  await sessionManager.signOut();

  window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: false }));
  expect(reload).not.toHaveBeenCalled();

  window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
  expect(reload).toHaveBeenCalled();
});
