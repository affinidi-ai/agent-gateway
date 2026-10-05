import React from 'react';
import { act, render, screen } from '@testing-library/react';
import App from './App';
import { apiClient, TERMS_ACCEPTANCE_REQUIRED_EVENT, TERMS_OPERATIONAL_FAILURE_EVENT } from './api';

jest.mock('./api', () => ({
  TERMS_ACCEPTANCE_REQUIRED_EVENT: 'terms-acceptance-required',
  TERMS_OPERATIONAL_FAILURE_EVENT: 'terms-operational-failure',
  apiClient: { fetch: jest.fn() },
  sessionManager: { logout: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('./pages/LoginPage', () => () => <div data-testid="mock-login" />);
jest.mock('./pages/AuthenticatedApp', () => () => <div data-testid="mock-authenticated" />);
jest.mock('./pages/TermsConsentPage', () => () => <div data-testid="mock-terms-consent" />);

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
