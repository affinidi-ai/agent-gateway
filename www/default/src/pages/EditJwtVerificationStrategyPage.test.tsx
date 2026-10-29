import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../context/PageTitleContext';
import EditJwtVerificationStrategyPage from './EditJwtVerificationStrategyPage';

const mockFetch = jest.fn();
jest.mock('../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));

const SERVER = {
  issuer: 'https://idp.example.com',
  metadata_url: 'https://idp.example.com/.well-known/openid-configuration',
  token_endpoint: 'https://idp.example.com/token',
  jwks_uri: 'https://idp.example.com/jwks.json',
};

const STORED = {
  id: 's1',
  name: 'Idp',
  expected_issuer: 'https://idp.example.com',
  jwks_source: { type: 'remote', jwks_uri: 'https://idp.example.com/jwks.json' },
  authorization_server: SERVER,
};

const json = (body: unknown, ok = true) => ({
  ok,
  status: ok ? 200 : 422,
  statusText: ok ? 'OK' : 'Unprocessable',
  json: async () => body,
  text: async () => JSON.stringify(body),
});

let discoverReply: ReturnType<typeof json>;

beforeEach(() => {
  jest.clearAllMocks();
  discoverReply = json(SERVER);
  mockFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
    if (url.endsWith('/discover')) return discoverReply;
    if (url.endsWith('/validate-jwks-uri')) return json({ valid: true });
    if (url.endsWith('/s1') && !init?.method) return json(STORED);
    return json({});
  });
});

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
          <Route path="/settings" element={<div data-testid="settings" />} />
        </Routes>
      </PageTitleProvider>
    </MemoryRouter>
  );

const saved = () => {
  const call = mockFetch.mock.calls.find(
    ([url, init]) =>
      init &&
      ['POST', 'PUT'].includes(init.method) &&
      !String(url).endsWith('/discover') &&
      !String(url).endsWith('/validate-jwks-uri')
  );
  return call ? { url: call[0], method: call[1].method, body: JSON.parse(call[1].body) } : null;
};

const save = () =>
  fireEvent.click(screen.getByRole('button', { name: /save changes|create strategy/i }));

describe('Strategy discovery', () => {
  it('shows the pinned authorization server and keeps it when saving unchanged', async () => {
    renderPage('/jwt-verification-strategies/s1');
    const card = await screen.findByTestId('strategy-pinned-server');
    expect(card).toHaveTextContent('https://idp.example.com/token');
    save();
    await waitFor(() => expect(saved()).not.toBeNull());
    const request = saved()!;
    expect(request.method).toBe('PUT');
    expect(request.body).not.toHaveProperty('discover_metadata');
    expect(mockFetch.mock.calls.some(([u]) => String(u).endsWith('/validate-jwks-uri'))).toBe(
      false
    );
  });

  it('discovers, fills the JWKS URI and saves with discover_metadata true without a URI check', async () => {
    renderPage('/jwt-verification-strategies/new');
    fireEvent.change(await screen.findByLabelText(/^Name/), { target: { value: 'Idp' } });
    fireEvent.change(screen.getByLabelText(/^Expected Issuer/), {
      target: { value: 'https://idp.example.com' },
    });
    expect(screen.getByTestId('strategy-no-pin')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('strategy-discover-button'));
    expect(await screen.findByTestId('strategy-discover-success')).toBeInTheDocument();
    expect(screen.getByLabelText(/^JWKS URI/)).toHaveValue(SERVER.jwks_uri);
    expect(screen.getByTestId('strategy-pinned-server')).toHaveTextContent(SERVER.metadata_url);
    save();
    await waitFor(() => expect(saved()).not.toBeNull());
    const request = saved()!;
    expect(request.method).toBe('POST');
    expect(request.body.discover_metadata).toBe(true);
    expect(request.body.jwks_source).toEqual({ type: 'remote', jwks_uri: SERVER.jwks_uri });
    expect(mockFetch.mock.calls.some(([u]) => String(u).endsWith('/validate-jwks-uri'))).toBe(
      false
    );
  });

  it('shows a generic alert when discovery fails and pins nothing', async () => {
    discoverReply = json({ error: 'resolved 10.0.0.1' }, false);
    renderPage('/jwt-verification-strategies/new');
    fireEvent.change(await screen.findByLabelText(/^Expected Issuer/), {
      target: { value: 'https://idp.example.com' },
    });
    fireEvent.click(screen.getByTestId('strategy-discover-button'));
    const alert = await screen.findByTestId('strategy-discover-error');
    expect(alert).toHaveAttribute('role', 'alert');
    expect(alert).not.toHaveTextContent('10.0.0.1');
    expect(screen.queryByTestId('strategy-pinned-server')).not.toBeInTheDocument();
  });

  it('refuses to discover a non-https issuer without calling the gateway', async () => {
    renderPage('/jwt-verification-strategies/new');
    fireEvent.change(await screen.findByLabelText(/^Expected Issuer/), {
      target: { value: 'http://idp.example.com' },
    });
    fireEvent.click(screen.getByTestId('strategy-discover-button'));
    expect(await screen.findByTestId('strategy-discover-error')).toHaveTextContent(/https/i);
    expect(mockFetch.mock.calls.some(([u]) => String(u).endsWith('/discover'))).toBe(false);
  });

  it('sends discover_metadata false after clearing the pinned metadata', async () => {
    renderPage('/jwt-verification-strategies/s1');
    await screen.findByTestId('strategy-pinned-server');
    fireEvent.click(screen.getByTestId('strategy-pinned-clear'));
    expect(screen.queryByTestId('strategy-pinned-server')).not.toBeInTheDocument();
    save();
    await waitFor(() => expect(saved()).not.toBeNull());
    expect(saved()!.body.discover_metadata).toBe(false);
  });

  it('warns and clears the pin when the keys become static', async () => {
    renderPage('/jwt-verification-strategies/s1');
    await screen.findByTestId('strategy-pinned-server');
    fireEvent.click(screen.getByLabelText(/Static Keys/));
    expect(screen.getByTestId('strategy-static-pin-warning')).toHaveTextContent(
      /clears the pinned/i
    );
    expect(screen.getByTestId('strategy-discover-button')).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/JWK Array/), { target: { value: '[]' } });
    save();
    await waitFor(() => expect(saved()).not.toBeNull());
    expect(saved()!.body.discover_metadata).toBe(false);
    expect(saved()!.body.jwks_source).toEqual({ type: 'static', jwks: [] });
  });

  it('flags a pin that no longer matches an edited issuer and still omits discover_metadata', async () => {
    renderPage('/jwt-verification-strategies/s1');
    await screen.findByTestId('strategy-pinned-server');
    fireEvent.change(screen.getByLabelText(/^Expected Issuer/), {
      target: { value: 'https://other.example.com' },
    });
    const stale = screen.getByTestId('strategy-pinned-stale');
    expect(stale).toHaveTextContent(
      /the save still succeeds and clears the pin when the issuer changed/i
    );
    expect(stale).not.toHaveTextContent(/save fails/i);
    save();
    await waitFor(() => expect(saved()).not.toBeNull());
    expect(saved()!.body).not.toHaveProperty('discover_metadata');
  });

  it('shows no stale pin warning while the issuer matches the pin', async () => {
    renderPage('/jwt-verification-strategies/s1');
    await screen.findByTestId('strategy-pinned-server');
    expect(screen.queryByTestId('strategy-pinned-stale')).not.toBeInTheDocument();
  });

  it('still requires the JWKS URI check for a new URI typed by hand', async () => {
    renderPage('/jwt-verification-strategies/new');
    fireEvent.change(await screen.findByLabelText(/^Name/), { target: { value: 'Manual' } });
    fireEvent.change(screen.getByLabelText(/^Expected Issuer/), {
      target: { value: 'https://idp.example.com' },
    });
    fireEvent.change(screen.getByLabelText(/^JWKS URI/), {
      target: { value: 'https://idp.example.com/keys' },
    });
    fireEvent.click(screen.getByRole('button', { name: /create strategy/i }));
    expect(await screen.findByText(/verify the JWKS URI is reachable/i)).toBeInTheDocument();
    expect(saved()).toBeNull();
  });
});
