import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import App from './App';
import {
  apiClient,
  sessionManager,
  TERMS_ACCEPTANCE_REQUIRED_EVENT,
  TERMS_OPERATIONAL_FAILURE_EVENT,
} from './api';

jest.mock('./api', () => ({
  TERMS_ACCEPTANCE_REQUIRED_EVENT: 'terms-acceptance-required',
  TERMS_OPERATIONAL_FAILURE_EVENT: 'terms-operational-failure',
  apiClient: { fetch: jest.fn() },
  sessionManager: { signOut: jest.fn() },
}));
jest.mock('./pages/LoginPage', () => () => <div data-testid="mock-login" />);
jest.mock('./pages/AuthenticatedApp', () => ({ onLogout }: { onLogout: () => void }) => (
  <button type="button" data-testid="mock-authenticated" onClick={onLogout} />
));
jest.mock('./pages/TermsConsentPage', () => ({ onLogout }: { onLogout: () => void }) => (
  <button type="button" data-testid="mock-terms-consent" onClick={onLogout} />
));
jest.mock('./pages/CliConsentPage', () => () => <div data-testid="mock-cli-consent" />);

test('moves an authenticated app into consent state after a protected API rejection', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  render(<App />);
  expect(await screen.findByTestId('mock-authenticated')).toBeInTheDocument();

  act(() => window.dispatchEvent(new Event(TERMS_ACCEPTANCE_REQUIRED_EVENT)));

  expect(await screen.findByTestId('mock-terms-consent')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-authenticated')).not.toBeInTheDocument();
});

test('blocks an authenticated app after a runtime Terms operational failure', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  render(<App />);
  expect(await screen.findByTestId('mock-authenticated')).toBeInTheDocument();

  act(() => window.dispatchEvent(new Event(TERMS_OPERATIONAL_FAILURE_EVENT)));

  expect(await screen.findByTestId('page-terms-operational-error')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-authenticated')).not.toBeInTheDocument();
});

test('shows the CLI consent page instead of the dashboard on the consent route', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );
  window.history.pushState({}, '', '/cli-consent');

  render(<App />);

  expect(await screen.findByTestId('mock-cli-consent')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-authenticated')).not.toBeInTheDocument();
  window.history.pushState({}, '', '/');
});

const consentPending = () =>
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

test('signing out shows the sign-in page when the dashboard stays', async () => {
  consentPending();
  (sessionManager.signOut as jest.Mock).mockResolvedValue(false);
  render(<App />);

  fireEvent.click(await screen.findByTestId('mock-terms-consent'));

  expect(await screen.findByTestId('mock-login')).toBeInTheDocument();
  expect(sessionManager.signOut).toHaveBeenCalled();
});

test('signing out shows only the loader while the browser goes to the provider to sign out', async () => {
  consentPending();
  let leave: (leaving: boolean) => void = () => {};
  (sessionManager.signOut as jest.Mock).mockReturnValue(
    new Promise<boolean>(resolve => {
      leave = resolve;
    })
  );
  render(<App />);

  fireEvent.click(await screen.findByTestId('mock-terms-consent'));
  await act(async () => leave(true));

  expect(screen.getByRole('status')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-terms-consent')).not.toBeInTheDocument();
  expect(screen.queryByTestId('mock-login')).not.toBeInTheDocument();
});

test('signing out takes the dashboard down before the sign-out starts', async () => {
  (apiClient.fetch as jest.Mock).mockResolvedValue(
    new Response(JSON.stringify({ authenticated: true, consent_required: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );
  let dashboardWhenSigningOut: HTMLElement | null | undefined;
  (sessionManager.signOut as jest.Mock).mockImplementation(() => {
    dashboardWhenSigningOut = screen.queryByTestId('mock-authenticated');
    return Promise.resolve(false);
  });
  render(<App />);

  fireEvent.click(await screen.findByTestId('mock-authenticated'));

  expect(await screen.findByTestId('mock-login')).toBeInTheDocument();
  expect(sessionManager.signOut).toHaveBeenCalledTimes(1);
  expect(dashboardWhenSigningOut).toBeNull();
});
