import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { apiClient } from '../../api';
import { PageTitleProvider } from '../../context/PageTitleContext';
import EditJwtVerificationStrategyPage from '../EditJwtVerificationStrategyPage';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
  },
}));

const response = (data: unknown) =>
  Promise.resolve({
    ok: true,
    statusText: 'OK',
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  });

const storedStrategy = {
  id: 'strategy-1',
  name: 'Entra callers',
  expected_issuer: 'https://login.example.com/tenant/v2.0',
  principal_claim: 'oid',
  jwks_source: { type: 'static', jwks: [] },
};

const renderPage = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <PageTitleProvider>
        <Routes>
          <Route
            path="/jwt-verification-strategies/new"
            element={<EditJwtVerificationStrategyPage />}
          />
          <Route
            path="/jwt-verification-strategies/:id"
            element={<EditJwtVerificationStrategyPage />}
          />
          <Route path="/settings" element={<div data-testid="settings-page" />} />
        </Routes>
      </PageTitleProvider>
    </MemoryRouter>
  );

const sentBody = (method: string) => {
  const call = (apiClient.fetch as jest.Mock).mock.calls.find(
    ([, init]: [string, RequestInit | undefined]) => init?.method === method
  );
  expect(call).toBeDefined();
  return JSON.parse(call[1].body as string);
};

const fillNewStrategy = (principalClaim: string) => {
  fireEvent.change(screen.getByRole('textbox', { name: /^name/i }), {
    target: { value: 'Entra callers' },
  });
  fireEvent.change(screen.getByRole('textbox', { name: /^expected issuer/i }), {
    target: { value: 'https://login.example.com/tenant/v2.0' },
  });
  fireEvent.change(screen.getByTestId('jwt-strategy-editor-principal-claim-input'), {
    target: { value: principalClaim },
  });
  fireEvent.click(screen.getByRole('radio', { name: /static keys/i }));
  fireEvent.change(screen.getByRole('textbox', { name: /jwk array/i }), {
    target: { value: '[]' },
  });
};

describe('EditJwtVerificationStrategyPage caller identity claim', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.fetch as jest.Mock).mockImplementation(() => response(storedStrategy));
  });

  it('sends the claim a new strategy names', async () => {
    renderPage('/jwt-verification-strategies/new');
    fillNewStrategy(' oid ');
    fireEvent.click(screen.getByTestId('jwt-strategy-editor-save-button'));

    await screen.findByTestId('settings-page');
    expect(sentBody('POST').principal_claim).toBe('oid');
  });

  it("shows a save's warning, such as another claim for the same issuer", async () => {
    (apiClient.fetch as jest.Mock).mockImplementation(() =>
      Promise.resolve({
        ok: true,
        statusText: 'Created',
        headers: { get: () => '299 - "an issuer names callers by one claim in a tenant"' },
        json: () => Promise.resolve(storedStrategy),
        text: () => Promise.resolve(JSON.stringify(storedStrategy)),
      })
    );
    renderPage('/jwt-verification-strategies/new');
    fillNewStrategy('oid');
    fireEvent.click(screen.getByTestId('jwt-strategy-editor-save-button'));

    await screen.findByTestId('settings-page');
    expect(showToast).toHaveBeenCalledWith(
      'warning',
      'an issuer names callers by one claim in a tenant',
      expect.anything()
    );
  });

  it('sends no claim for a new strategy whose field is blank', async () => {
    renderPage('/jwt-verification-strategies/new');
    fillNewStrategy('');
    fireEvent.click(screen.getByTestId('jwt-strategy-editor-save-button'));

    await screen.findByTestId('settings-page');
    expect(sentBody('POST')).not.toHaveProperty('principal_claim');
  });

  it('shows the stored claim read-only on edit and leaves it out of the update', async () => {
    renderPage('/jwt-verification-strategies/strategy-1');
    const field = await screen.findByTestId('jwt-strategy-editor-principal-claim-input');
    await waitFor(() => expect(field).toHaveValue('oid'));
    expect(field).toBeDisabled();

    fireEvent.click(screen.getByTestId('jwt-strategy-editor-save-button'));

    await screen.findByTestId('settings-page');
    expect(sentBody('PUT')).not.toHaveProperty('principal_claim');
  });
});
