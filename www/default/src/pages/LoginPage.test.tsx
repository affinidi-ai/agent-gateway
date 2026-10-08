import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { apiClient } from '../api';
import { authenticateWithPasskey } from '../utils/passkeys';
import LoginPage from './LoginPage';

jest.mock('../api', () => ({
  apiClient: { fetch: jest.fn() },
  sessionManager: {
    didSessionExpire: () => false,
    clearSessionExpiredError: jest.fn(),
    getSessionToken: () => null,
    getCookie: () => null,
  },
}));

jest.mock('../utils/passkeys', () => ({
  isWebAuthnSupported: () => true,
  isPlatformAuthenticatorAvailable: () => Promise.resolve(false),
  registerPasskey: jest.fn(),
  authenticateWithPasskey: jest.fn(),
}));

const ORIGIN = 'http://localhost';
const CLI_TARGET = '/api/auth/cli/authorize?port=52111&state=st&challenge=ch';
const HOSTILE_NEXT = 'https://evil.example/steal';

const originalLocation = window.location;

function setLocation(pathname: string, search: string) {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...originalLocation,
      origin: ORIGIN,
      pathname,
      search,
      href: `${ORIGIN}${pathname}${search}`,
    },
  });
}

function nextQuery(next: string) {
  return `?next=${encodeURIComponent(next)}`;
}

function mockAuthMode(mode: 'passkey' | 'saml') {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ mode }), { headers: { 'Content-Type': 'application/json' } })
  );
}

async function signInWithPasskey(onLogin: () => void) {
  render(<LoginPage onLogin={onLogin} />);
  fireEvent.change(await screen.findByTestId('login-username'), { target: { value: 'alice' } });
  fireEvent.click(screen.getByTestId('login-authenticate-button'));
}

async function signInWithSaml() {
  render(<LoginPage onLogin={jest.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: /sign in/i }));
}

beforeEach(() => {
  jest.resetAllMocks();
  (authenticateWithPasskey as jest.Mock).mockResolvedValue(undefined);
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
});

test('a passkey sign-in follows a valid next target', async () => {
  mockAuthMode('passkey');
  setLocation('/login', nextQuery(CLI_TARGET));
  const onLogin = jest.fn();

  await signInWithPasskey(onLogin);

  await waitFor(() => expect(window.location.href).toBe(CLI_TARGET));
  expect(onLogin).not.toHaveBeenCalled();
});

test('a passkey sign-in ignores a hostile next target', async () => {
  mockAuthMode('passkey');
  setLocation('/login', nextQuery(HOSTILE_NEXT));
  const onLogin = jest.fn();

  await signInWithPasskey(onLogin);

  await waitFor(() => expect(onLogin).toHaveBeenCalled());
  expect(window.location.href).toBe(`${ORIGIN}/login${nextQuery(HOSTILE_NEXT)}`);
});

test('a SAML sign-in forwards a valid next target', async () => {
  mockAuthMode('saml');
  setLocation('/login', nextQuery(CLI_TARGET));

  await signInWithSaml();

  await waitFor(() =>
    expect(window.location.href).toBe(`/api/saml/login?next=${encodeURIComponent(CLI_TARGET)}`)
  );
});

test('a SAML sign-in drops a hostile next target', async () => {
  mockAuthMode('saml');
  setLocation('/login', nextQuery(HOSTILE_NEXT));

  await signInWithSaml();

  await waitFor(() => expect(window.location.href).toBe('/api/saml/login'));
});

test('a SAML sign-in from a signed-out consent page returns to the CLI login flow', async () => {
  mockAuthMode('saml');
  setLocation('/cli-consent', '?port=52111&state=st&challenge=ch');

  await signInWithSaml();

  await waitFor(() =>
    expect(window.location.href).toBe(`/api/saml/login?next=${encodeURIComponent(CLI_TARGET)}`)
  );
});
