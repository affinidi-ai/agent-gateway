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

function mockAuthMode(mode: 'passkey' | 'saml' | 'oidc', label: string | null = null) {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ mode, label }), {
      headers: { 'Content-Type': 'application/json' },
    })
  );
}

async function signInWithPasskey(onLogin: () => void) {
  render(<LoginPage onLogin={onLogin} />);
  fireEvent.change(await screen.findByTestId('login-username'), { target: { value: 'alice' } });
  fireEvent.click(screen.getByTestId('login-authenticate-button'));
}

async function signInWithSso() {
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

  await signInWithSso();

  await waitFor(() =>
    expect(window.location.href).toBe(`/api/saml/login?next=${encodeURIComponent(CLI_TARGET)}`)
  );
});

test('a SAML sign-in drops a hostile next target', async () => {
  mockAuthMode('saml');
  setLocation('/login', nextQuery(HOSTILE_NEXT));

  await signInWithSso();

  await waitFor(() => expect(window.location.href).toBe('/api/saml/login'));
});

test('a SAML sign-in from a signed-out consent page returns to the CLI login flow', async () => {
  mockAuthMode('saml');
  setLocation('/cli-consent', '?port=52111&state=st&challenge=ch');

  await signInWithSso();

  await waitFor(() =>
    expect(window.location.href).toBe(`/api/saml/login?next=${encodeURIComponent(CLI_TARGET)}`)
  );
});

test('typing in the username field keeps the same input element so the caret stays put', async () => {
  mockAuthMode('passkey');
  setLocation('/login', '');
  render(<LoginPage onLogin={jest.fn()} />);

  const input = await screen.findByTestId('login-username');
  fireEvent.change(input, { target: { value: 'alice@example.com' } });
  fireEvent.change(screen.getByTestId('login-username'), {
    target: { value: 'aliceX@example.com' },
  });

  expect(screen.getByTestId('login-username')).toBe(input);
  expect((input as HTMLInputElement).value).toBe('aliceX@example.com');
});

test('an OIDC sign-in names the provider on its button and forwards a valid next target', async () => {
  mockAuthMode('oidc', 'Example Directory');
  setLocation('/login', nextQuery(CLI_TARGET));

  render(<LoginPage onLogin={jest.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Sign in with Example Directory' }));

  await waitFor(() =>
    expect(window.location.href).toBe(`/api/oidc/login?next=${encodeURIComponent(CLI_TARGET)}`)
  );
  expect(screen.queryByTestId('login-username')).not.toBeInTheDocument();
});

test('an OIDC sign-in drops a hostile next target', async () => {
  mockAuthMode('oidc', 'Example Directory');
  setLocation('/login', nextQuery(HOSTILE_NEXT));

  await signInWithSso();

  await waitFor(() => expect(window.location.href).toBe('/api/oidc/login'));
});

test.each([null, '', '   ', 42])(
  'an OIDC sign-in with the label %p falls back to SSO',
  async label => {
    (apiClient.fetch as jest.Mock).mockResolvedValue(
      new Response(JSON.stringify({ mode: 'oidc', label }), {
        headers: { 'Content-Type': 'application/json' },
      })
    );
    setLocation('/login', '');

    render(<LoginPage onLogin={jest.fn()} />);

    expect(await screen.findByTestId('login-sso-button')).toHaveTextContent(/^Sign in with SSO$/);
  }
);

test('an OIDC label is shown as text, never as markup', async () => {
  mockAuthMode('oidc', '<b>Corp</b>');
  setLocation('/login', '');

  render(<LoginPage onLogin={jest.fn()} />);

  const button = await screen.findByTestId('login-sso-button');
  expect(button).toHaveTextContent('Sign in with <b>Corp</b>');
  expect(screen.queryByText('Corp', { selector: 'b' })).not.toBeInTheDocument();
});

test('a SAML sign-in keeps its SSO button and ignores a label', async () => {
  mockAuthMode('saml', 'Example Directory');
  setLocation('/login', '');

  render(<LoginPage onLogin={jest.fn()} />);

  expect(await screen.findByTestId('login-sso-button')).toHaveTextContent(/^Sign in with SSO$/);
});
