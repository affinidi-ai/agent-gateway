import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { apiClient } from '../api';
import { authenticateWithPasskey, registerPasskey } from '../utils/passkeys';
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

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
}

function mockAuthMode(mode: 'passkey' | 'saml', setupRequired?: boolean) {
  const modeBody = setupRequired === undefined ? { mode } : { mode, setup_required: setupRequired };
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve(
      url === '/api/v1/terms/applicable' ? jsonResponse({ terms: [] }) : jsonResponse(modeBody)
    )
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

test('offers the setup token field when the gateway reports setup is required', async () => {
  mockAuthMode('passkey', true);

  render(<LoginPage onLogin={jest.fn()} />);

  const field = await screen.findByTestId('login-setup-token');
  expect(field).toHaveAttribute('type', 'password');
  expect(field).toHaveAttribute('autocomplete', 'one-time-code');
  expect(field).toHaveAttribute('maxlength', '256');
  expect(screen.getByText('Create your account')).toBeInTheDocument();
  expect(screen.getByTestId('login-register-button')).toBeInTheDocument();
});

test.each([false, undefined])(
  'offers no setup token field when setup is not required (%s)',
  async setupRequired => {
    mockAuthMode('passkey', setupRequired);

    render(<LoginPage onLogin={jest.fn()} />);

    expect(await screen.findByTestId('login-authenticate-button')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('login-mode-toggle'));
    expect(await screen.findByTestId('login-register-button')).toBeInTheDocument();
    expect(screen.queryByTestId('login-setup-token')).not.toBeInTheDocument();
  }
);

test('registers the first administrator with the trimmed setup token', async () => {
  mockAuthMode('passkey', true);
  const user = userEvent.setup();
  render(<LoginPage onLogin={jest.fn()} />);

  await user.type(await screen.findByTestId('login-setup-token'), '  first-admin-token  ');
  await user.type(screen.getByTestId('login-username'), 'alice');
  await waitFor(() => expect(screen.getByTestId('login-register-button')).toBeEnabled());
  await user.click(screen.getByTestId('login-register-button'));

  await waitFor(() =>
    expect(registerPasskey).toHaveBeenCalledWith('alice', [], 'first-admin-token')
  );
});

test('keeps registration disabled until a setup token is entered', async () => {
  mockAuthMode('passkey', true);
  const user = userEvent.setup();
  render(<LoginPage onLogin={jest.fn()} />);

  await user.type(await screen.findByTestId('login-username'), 'alice');
  await user.type(screen.getByTestId('login-setup-token'), '   ');

  expect(screen.getByTestId('login-register-button')).toBeDisabled();
  await user.type(screen.getByTestId('login-setup-token'), 'first-admin-token');
  await waitFor(() => expect(screen.getByTestId('login-register-button')).toBeEnabled());
});

test('drops the setup token field once the first administrator is registered', async () => {
  mockAuthMode('passkey', true);
  (registerPasskey as jest.Mock).mockResolvedValue({ success: true });
  const user = userEvent.setup();
  render(<LoginPage onLogin={jest.fn()} />);

  await user.type(await screen.findByTestId('login-setup-token'), 'first-admin-token');
  await user.type(screen.getByTestId('login-username'), 'alice');
  await waitFor(() => expect(screen.getByTestId('login-register-button')).toBeEnabled());
  await user.click(screen.getByTestId('login-register-button'));

  expect(
    await screen.findByText('Passkey registered successfully! You can now log in.')
  ).toBeInTheDocument();
  fireEvent.click(screen.getByTestId('login-mode-toggle'));
  expect(await screen.findByTestId('login-register-button')).toBeInTheDocument();
  expect(screen.queryByTestId('login-setup-token')).not.toBeInTheDocument();
});
