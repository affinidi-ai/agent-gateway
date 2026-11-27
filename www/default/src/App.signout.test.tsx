import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';

jest.mock('./context/AppContext', () => ({
  AppProvider: ({ children }: { children: React.ReactNode }) => children,
  useApp: () => ({
    state: { sidebarCollapsed: false, theme: 'light', settings: {} },
    actions: { connectWebSocket: () => {}, disconnectWebSocket: () => {} },
  }),
}));
jest.mock('./context/PermissionsContext', () => ({
  PermissionsProvider: ({ children }: { children: React.ReactNode }) => children,
  usePermissions: () => ({ loading: false, hasPermission: () => true }),
}));
jest.mock('./components/Sidebar', () => () => null);
jest.mock('./components/ScrollToTop', () => () => null);
jest.mock('./components/Header', () => ({ onLogout }: { onLogout: () => void }) => (
  <button type="button" onClick={onLogout}>
    Sign Out
  </button>
));
jest.mock('./pages/Dashboard', () => {
  const { useEffect } = jest.requireActual('react');
  return () => {
    useEffect(() => {
      const unsavedChanges = (event: Event) => event.preventDefault();
      globalThis.addEventListener('beforeunload', unsavedChanges);
      return () => globalThis.removeEventListener('beforeunload', unsavedChanges);
    }, []);
    return <div data-testid="page-dashboard" />;
  };
});
jest.mock('./pages/LoginPage', () => () => <div data-testid="mock-login" />);

const PROVIDER_SIGN_OUT = 'https://idp.example.com/logout?id_token_hint=h&state=s';
const originalLocation = window.location;
const assign = jest.fn();
let logoutAnswer: Record<string, unknown> = {};

const json = (body: unknown) =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

const fetchMock = jest.fn();

const logoutRequests = () => fetchMock.mock.calls.filter(([url]) => url === '/api/auth/logout');

const signOutFromTopbar = async () => {
  render(<App />);
  await screen.findByTestId('page-dashboard');
  fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
};

beforeEach(() => {
  fetchMock.mockImplementation((url: string) => {
    if (url === '/api/auth/check') return json({ authenticated: true, consent_required: false });
    if (url === '/api/auth/logout') return json(logoutAnswer);
    return json({});
  });
  global.fetch = fetchMock;
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...originalLocation, assign, pathname: '/', search: '', hash: '' },
  });
  sessionStorage.setItem('session_token', 'tok');
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
  sessionStorage.clear();
});

test('signing out from the topbar sends one sign-out request and shows the sign-in page', async () => {
  logoutAnswer = {};

  await signOutFromTopbar();

  expect(await screen.findByTestId('mock-login')).toBeInTheDocument();
  expect(logoutRequests()).toHaveLength(1);
  expect(assign).not.toHaveBeenCalled();
});

test('signing out from the topbar takes the dashboard and its leave-page prompt down before the browser leaves', async () => {
  logoutAnswer = { end_session_url: PROVIDER_SIGN_OUT };
  const whenLeaving: { dashboard?: HTMLElement | null; prompted?: boolean } = {};
  assign.mockImplementation(() => {
    whenLeaving.dashboard = screen.queryByTestId('page-dashboard');
    whenLeaving.prompted = !window.dispatchEvent(new Event('beforeunload', { cancelable: true }));
  });

  await signOutFromTopbar();

  await waitFor(() => expect(assign).toHaveBeenCalledWith(PROVIDER_SIGN_OUT));
  expect(whenLeaving).toEqual({ dashboard: null, prompted: false });
  expect(logoutRequests()).toHaveLength(1);
  expect(screen.getByRole('status')).toBeInTheDocument();
  expect(screen.queryByTestId('mock-login')).not.toBeInTheDocument();
});
