import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { apiClient } from '../../api';
import CliConsentPage from '.';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn(), cliConsent: jest.fn() },
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
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    jsonResponse({ authenticated: true, username: 'alice' })
  );
  (apiClient.cliConsent as jest.Mock).mockResolvedValue(
    jsonResponse({ redirect_url: REDIRECT_URL })
  );
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
});

test('shows the signed-in username and the loopback port', async () => {
  render(<CliConsentPage />);

  expect(await screen.findByTestId('cli-consent-username')).toHaveTextContent('Signed in as alice');
  expect(screen.getByTestId('cli-consent-target')).toHaveTextContent('Return to 127.0.0.1:52111');
  expect(screen.getByText('Allow the CLI to sign in as you?')).toBeInTheDocument();
});

test('Allow sends the request and sends the browser to the returned loopback URL', async () => {
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow-button'));

  await waitFor(() => expect(window.location.href).toBe(REDIRECT_URL));
  expect(apiClient.cliConsent).toHaveBeenCalledWith({
    port: 52111,
    state: 'state-123',
    challenge: CHALLENGE,
  });
});

test('Allow refuses a redirect that does not point at the requested loopback port', async () => {
  (apiClient.cliConsent as jest.Mock).mockResolvedValue(
    jsonResponse({ redirect_url: 'https://evil.example/callback?code=x' })
  );
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow-button'));

  expect(await screen.findByTestId('cli-consent-error')).toBeInTheDocument();
  expect(window.location.href).not.toContain('evil.example');
});

test('Allow refuses a redirect to port 52111 when port 5211 was requested', async () => {
  const lookalike = 'http://127.0.0.1:52111/callback?code=x&state=state-123';
  setLocation(`?port=5211&state=state-123&challenge=${CHALLENGE}`);
  (apiClient.cliConsent as jest.Mock).mockResolvedValue(jsonResponse({ redirect_url: lookalike }));
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow-button'));

  expect(await screen.findByTestId('cli-consent-error')).toBeInTheDocument();
  expect(window.location.href).not.toBe(lookalike);
});

test('shows an error and allows a retry when the endpoint fails', async () => {
  (apiClient.cliConsent as jest.Mock).mockResolvedValue(new Response('too many', { status: 429 }));
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-allow-button'));

  expect(await screen.findByTestId('cli-consent-error')).toHaveTextContent('Too many sign-ins');
  expect(screen.getByTestId('cli-consent-allow-button')).toBeEnabled();
});

test('Cancel shows the close tab message and never calls the consent endpoint', async () => {
  render(<CliConsentPage />);

  fireEvent.click(await screen.findByTestId('cli-consent-cancel-button'));

  expect(screen.getByTestId('cli-consent-cancelled')).toHaveTextContent('You can close this tab');
  expect(apiClient.cliConsent).not.toHaveBeenCalled();
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
  expect(screen.queryByTestId('cli-consent-allow-button')).not.toBeInTheDocument();
  expect(apiClient.fetch).not.toHaveBeenCalled();
});
