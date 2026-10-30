import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import SurfaceDetailPage from '../SurfaceDetailPage';
import { apiClient } from '../../api';
import type { AgentSurface } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../../components/surface-builder/SurfaceCanvas', () => ({
  getIncompleteReason: () => null,
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));
jest.mock('../../context/PageTitleContext', () => ({ usePageTitle: () => undefined }));
jest.mock('../../context/AppContext', () => ({
  useApp: () => ({ getCurrentStats: () => undefined }),
}));
jest.mock('../../components/surface-builder/hooks/useSurfacePolicyDefinitions', () => ({
  useSurfacePolicyDefinitions: () => ({ status: 'loaded', ids: new Set<string>() }),
}));
jest.mock('../../components/surface-builder/hooks/useSurfaceBuilder', () => {
  const actual = jest.requireActual('../../components/surface-builder/hooks/useSurfaceBuilder');
  return {
    ...actual,
    useSurfaceBuilder: (...args: unknown[]) => {
      const builder = actual.useSurfaceBuilder(...args);
      return {
        ...builder,
        hasIncompleteNodes: false,
        hasValidationErrors: false,
        hasDependencyErrors: false,
        dependencyErrors: [],
        state: {
          ...builder.state,
          nodes: builder.state.nodes.map((n: object) => ({ ...n, configured: true })),
        },
      };
    },
  };
});
jest.mock(
  '../../components/surface-builder/SurfaceFormShell',
  () => (props: any) => MockSurfaceFormShell(props)
);

function MockSurfaceFormShell(props: any) {
  return (
    <div>
      {props.topBanner}
      <output data-testid="meta-warnings">{(props.saveWarnings ?? []).join('|')}</output>
      {props.manageActions}
    </div>
  );
}

function LocationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="location-state">{JSON.stringify(location.state)}</output>
      <output data-testid="location-url">{`${location.pathname}${location.search}${location.hash}`}</output>
      <button onClick={() => navigate('/surfaces/s2')}>Open another surface</button>
    </>
  );
}

const surface = {
  surface_id: 's1',
  name: 'agent',
  status: 'active',
  access_point: { listen_address: 'https://gw.example', route: '/agents/a', protocol: 'a2a' },
  target: { endpoint: 'https://agent.example' },
} as unknown as AgentSurface;

const createWarning =
  "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: 0.0.0.0:8080";

const renderAt = (state: unknown, search = '', hash = '') =>
  render(
    <MemoryRouter initialEntries={[{ pathname: '/surfaces/s1', search, hash, state }]}>
      <Routes>
        <Route
          path="/surfaces/:surfaceId"
          element={
            <>
              <SurfaceDetailPage />
              <LocationProbe />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );

beforeEach(() => {
  jest.restoreAllMocks();
  (showToast as jest.Mock).mockReset();
  jest.spyOn(apiClient, 'getSurface').mockResolvedValue(surface);
});

describe('SurfaceDetailPage save warnings', () => {
  it('shows the warnings a create carried here, then clears them from the route state', async () => {
    renderAt({ saveWarnings: [createWarning] });
    await screen.findByTestId('meta-warnings');

    expect(screen.getByTestId('meta-warnings')).toHaveTextContent(createWarning);
    expect(screen.getByTestId('surface-save-warnings')).toHaveTextContent(createWarning);
    expect(screen.getByTestId('location-state')).toHaveTextContent('null');
  });

  it('keeps the query string and hash when it clears the route state', async () => {
    renderAt({ saveWarnings: [createWarning] }, '?tab=elements', '#crm');
    await screen.findByTestId('meta-warnings');

    expect(screen.getByTestId('location-state')).toHaveTextContent('null');
    expect(screen.getByTestId('location-url')).toHaveTextContent('/surfaces/s1?tab=elements#crm');
  });

  it('does not show one surface warnings on another surface', async () => {
    renderAt({ saveWarnings: [createWarning] });
    await screen.findByTestId('meta-warnings');
    expect(screen.getByTestId('meta-warnings')).toHaveTextContent(createWarning);

    fireEvent.click(screen.getByText('Open another surface'));

    await waitFor(() => expect(apiClient.getSurface).toHaveBeenCalledWith('s2'));
    expect(await screen.findByTestId('meta-warnings')).toBeEmptyDOMElement();
    expect(screen.queryByTestId('surface-save-warnings')).toBeNull();
  });

  it('ignores route state that is not a list of warnings', async () => {
    renderAt({ saveWarnings: [1] });
    await screen.findByTestId('meta-warnings');

    expect(screen.getByTestId('meta-warnings')).toBeEmptyDOMElement();
  });

  it('shows the warnings an update answered with, in the banner and the one toast', async () => {
    const updateWarning = createWarning.replace('crm', 'hr');
    jest.spyOn(apiClient, 'updateSurface').mockImplementation(async (_id, _payload, options) => {
      options?.onWarnings?.([updateWarning]);
      return surface;
    });
    renderAt(null);
    fireEvent.click(await screen.findByTitle('Save changes'));
    await waitFor(() => expect(showToast).toHaveBeenCalled());

    expect(screen.getByTestId('meta-warnings')).toHaveTextContent(updateWarning);
    expect(screen.getByTestId('surface-save-warnings')).toHaveTextContent(updateWarning);
    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(
      'error',
      expect.stringContaining(updateWarning),
      expect.objectContaining({ autoRemove: true })
    );
  });
});
