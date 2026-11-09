import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient, sessionManager } from '../api';
import LoginPage from './LoginPage';

jest.mock('../api', () => ({
  apiClient: { fetch: jest.fn() },
  sessionManager: {
    didSessionExpire: () => false,
    clearSessionExpiredError: jest.fn(),
    getSessionToken: jest.fn(),
    forgetSessionToken: jest.fn(),
    getCookie: () => null,
  },
}));

jest.mock('../utils/passkeys', () => ({
  isWebAuthnSupported: () => true,
  isPlatformAuthenticatorAvailable: () => Promise.resolve(false),
  registerPasskey: jest.fn(),
  authenticateWithPasskey: jest.fn(),
}));

const originalLocation = window.location;

const setLocation = (pathname: string) =>
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...originalLocation,
      origin: 'http://localhost',
      pathname,
      search: '',
      href: `http://localhost${pathname}`,
    },
  });

const answer = (check: Record<string, unknown>) =>
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve(
      new Response(JSON.stringify(url.includes('/auth/check') ? check : { mode: 'passkey' }), {
        headers: { 'Content-Type': 'application/json' },
      })
    )
  );

beforeEach(() => {
  jest.clearAllMocks();
  setLocation('/login');
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
});

describe('a session token left in the browser', () => {
  test('is dropped, without a redirect, when the server says it is not signed in', async () => {
    // The check answers 200 with `authenticated: false` for a token the server no
    // longer knows (a wiped or restarted gateway). Redirecting to the dashboard on
    // the 200 alone sent the page round in circles with the app, which shows this
    // page for the same answer.
    (sessionManager.getSessionToken as jest.Mock).mockReturnValue('left-over-token');
    answer({ authenticated: false, username: null, consent_required: false });

    render(<LoginPage onLogin={jest.fn()} />);

    expect(await screen.findByTestId('login-username')).toBeInTheDocument();
    expect(window.location.href).toBe('http://localhost/login');
    expect(sessionManager.forgetSessionToken).toHaveBeenCalled();
  });

  test('still goes to the dashboard when the server says it is signed in', async () => {
    (sessionManager.getSessionToken as jest.Mock).mockReturnValue('good-token');
    answer({ authenticated: true, username: 'alice', consent_required: false });

    render(<LoginPage onLogin={jest.fn()} />);

    await waitFor(() => expect(window.location.href).toBe('/'));
    expect(sessionManager.forgetSessionToken).not.toHaveBeenCalled();
  });
});
