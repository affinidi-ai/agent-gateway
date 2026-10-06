import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { apiClient } from '../../api';
import CliConsentPage from '.';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const CHALLENGE = 'a'.repeat(43);
const VALID_SEARCH = `?port=52111&state=state-123&challenge=${CHALLENGE}`;
const REDIRECT_URL = 'http://127.0.0.1:52111/callback?code=the-code&state=state-123';

const originalLocation = window.location;

function setLocation(search: string) {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...originalLocation, search, href: `http://localhost/cli-consent${search}` },
  });
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  jest.resetAllMocks();
  setLocation(VALID_SEARCH);
  (apiClient.fetch as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/auth/check') {
      return jsonResponse({ authenticated: true, username: 'alice' });
    }
    return jsonResponse({ redirect_url: REDIRECT_URL });
  });
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
});

function consentCalls() {
  return (apiClient.fetch as jest.Mock).mock.calls.filter(
    ([url]) => url === '/api/auth/cli/consent'
  );
}

test('shows the signed-in username and the loopback port', async () => {
  render(<CliConsentPage />);

  expect(await screen.findByTestId('cli-consent-username')).toHaveTextContent('Signed in as alice');
  expect(screen.getByTestId('cli-consent-target')).toHaveTextContent('Return to 127.0.0.1:52111');
  expect(screen.getByText('Allow the CLI to sign in as you?')).toBeInTheDocument();
});

test('Allow posts the request as JSON and sends the browser to the returned loopback URL', async () => {
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow'));

  await waitFor(() => expect(window.location.href).toBe(REDIRECT_URL));
  const [, init] = consentCalls()[0];
  expect(init.method).toBe('POST');
  expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
  expect(JSON.parse(init.body)).toEqual({ port: 52111, state: 'state-123', challenge: CHALLENGE });
});

test('Allow refuses a redirect that does not point at the requested loopback port', async () => {
  (apiClient.fetch as jest.Mock).mockImplementation(async (url: string) =>
    url === '/api/auth/check'
      ? jsonResponse({ authenticated: true, username: 'alice' })
      : jsonResponse({ redirect_url: 'https://evil.example/callback?code=x' })
  );
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow'));

  expect(await screen.findByTestId('cli-consent-error')).toBeInTheDocument();
  expect(window.location.href).not.toContain('evil.example');
});

test('shows an error and allows a retry when the endpoint fails', async () => {
  (apiClient.fetch as jest.Mock).mockImplementation(async (url: string) =>
    url === '/api/auth/check'
      ? jsonResponse({ authenticated: true, username: 'alice' })
      : new Response('too many', { status: 429 })
  );
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow'));

  expect(await screen.findByTestId('cli-consent-error')).toHaveTextContent('Too many sign-ins');
  expect(screen.getByTestId('cli-consent-allow')).toBeEnabled();
});

test('Cancel shows the close tab message and never calls the consent endpoint', async () => {
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-cancel'));

  expect(screen.getByTestId('cli-consent-cancelled')).toHaveTextContent('You can close this tab');
  expect(consentCalls()).toHaveLength(0);
});

test.each([
  ['a port below 1024', `?port=80&state=s&challenge=${CHALLENGE}`],
  ['a non-numeric port', `?port=abc&state=s&challenge=${CHALLENGE}`],
  ['a port above 65535', `?port=70000&state=s&challenge=${CHALLENGE}`],
  ['a missing state', `?port=52111&challenge=${CHALLENGE}`],
  ['a challenge of the wrong length', '?port=52111&state=s&challenge=short'],
  ['a challenge with invalid characters', `?port=52111&state=s&challenge=${'a'.repeat(42)}/`],
])('shows an error for %s and does not call the API', async (_label, search) => {
  setLocation(search);
  render(<CliConsentPage />);

  expect(await screen.findByTestId('cli-consent-invalid')).toBeInTheDocument();
  expect(screen.queryByTestId('cli-consent-allow')).not.toBeInTheDocument();
  expect(apiClient.fetch).not.toHaveBeenCalled();
});
