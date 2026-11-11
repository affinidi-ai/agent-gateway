import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import SurfaceDetailPage from '../SurfaceDetailPage';
import { apiClient } from '../../api';
import type { AgentSurface } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({
  ...jest.requireActual('../../utils/toaster'),
  showToast: jest.fn(),
}));
jest.mock('../../components/surface-builder/SurfaceCanvas', () => ({
  getIncompleteReason: () => null,
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../context/PageTitleContext', () => ({ usePageTitle: () => undefined }));
jest.mock('../../context/AppContext', () => ({
  useApp: () => ({ getCurrentStats: () => null }),
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
  const setPublic = (value: boolean) => {
    const ap = props.builder.state.nodes.find((n: any) => n.id === 'access-point');
    props.builder.handleNodeUpdate('access-point', { ...ap.config, public: value });
  };
  return (
    <div>
      {props.topBanner}
      <output data-testid="meta-warnings">{(props.saveWarnings ?? []).join('|')}</output>
      <button onClick={() => setPublic(true)}>Turn on Public access</button>
      <button onClick={() => setPublic(false)}>Close Access Point</button>
      <output data-testid="access-point-notice">{props.accessPointNotice ?? ''}</output>
      <output data-testid="legacy-access-point">{String(props.legacyAccessPoint)}</output>
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
      'warning',
      expect.stringContaining(updateWarning),
      expect.objectContaining({ autoRemove: true })
    );
  });
});

const PUBLIC_MESSAGE =
  'This Access Point is public. Anyone who can reach it can call your agent without credentials.';
const NOT_READY_MESSAGE =
  'This Access Point is not ready for external access. Add source authentication (a caller_authentication method), or set access_point.public to true to allow callers without credentials.';
const LEGACY_OPEN_MESSAGE =
  'This Access Point is neither closed nor public, and it admits callers without credentials. Add source authentication, or set access_point.public to false to close it or to true to keep it open.';

const API_KEY_AUTH = {
  methods: [
    {
      type: 'api_key',
      extraction: { source: 'http_header', field: 'X-Api-Key' },
      secret_id: 'sec-1',
    },
  ],
};

const stored = (accessPoint: Record<string, unknown>): AgentSurface =>
  ({
    surface_id: 'srf-1',
    name: 'orders',
    description: '',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gw.example',
      route: '/agents/orders',
      protocol: 'mcp',
      ...accessPoint,
    },
    target: { endpoint: 'https://agent.example' },
  }) as unknown as AgentSurface;

const toast = showToast as jest.Mock;

describe('SurfaceDetailPage save', () => {
  let updateSurface: jest.SpyInstance;

  const renderPage = async (surface: AgentSurface, warnings: string[] = []) => {
    jest.spyOn(apiClient, 'getSurface').mockResolvedValue(surface);
    updateSurface.mockImplementation(
      async (
        _id: string,
        payload: Partial<AgentSurface>,
        options?: { onWarnings?: (warnings: string[]) => void }
      ) => {
        options?.onWarnings?.(warnings);
        return { ...surface, ...payload };
      }
    );
    render(
      <MemoryRouter initialEntries={['/surfaces/srf-1']}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<SurfaceDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByTestId('surface-save-button');
  };

  // A save shows one toast: success, or the saved message with its warnings.
  const save = async () => {
    fireEvent.click(screen.getByTestId('surface-save-button'));
    await waitFor(() => expect(updateSurface).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(toast).toHaveBeenCalledTimes(1));
    return updateSurface.mock.calls[0][1] as AgentSurface;
  };

  const warningToasts = () => toast.mock.calls.filter(c => c[0] === 'warning').map(c => c[1]);

  beforeEach(() => {
    jest.restoreAllMocks();
    toast.mockReset();
    updateSurface = jest.spyOn(apiClient, 'updateSurface');
  });

  it("hides the response's public warning after Public access is turned on", async () => {
    await renderPage(
      stored({ public: false, caller_authentication: { ...API_KEY_AUTH, on_failure: 'reject' } }),
      [PUBLIC_MESSAGE]
    );
    fireEvent.click(screen.getByText('Turn on Public access'));

    const sent = await save();

    expect(sent.access_point.public).toBe(true);
    expect(sent.access_point.caller_authentication).not.toHaveProperty('on_failure');
    expect(warningToasts()).toEqual([]);
    expect(toast).toHaveBeenCalledWith('success', 'Agent Surface "orders" saved');
    expect(screen.queryByTestId('surface-save-warnings')).not.toBeInTheDocument();
  });

  it('saves a surface stored without public and no Caller Context, showing no gateway warning', async () => {
    await renderPage(stored({}), [LEGACY_OPEN_MESSAGE]);
    expect(screen.getByTestId('legacy-access-point')).toHaveTextContent('true');

    const sent = await save();

    expect(sent.access_point).not.toHaveProperty('public');
    expect(warningToasts()).toEqual([]);
    expect(screen.queryByTestId('surface-save-warnings')).not.toBeInTheDocument();
    expect(toast.mock.calls.some(c => c[0] === 'error')).toBe(false);
  });

  it('closes a surface stored without public once the operator closes it', async () => {
    await renderPage(
      stored({ caller_authentication: { ...API_KEY_AUTH, on_failure: 'continue' } })
    );
    fireEvent.click(screen.getByText('Close Access Point'));

    const sent = await save();

    expect(sent.access_point.public).toBe(false);
    expect(sent.access_point.caller_authentication).not.toHaveProperty('on_failure');
    await waitFor(() =>
      expect(screen.getByTestId('legacy-access-point')).toHaveTextContent('false')
    );
  });

  it('saves a closed surface with no Caller Context, showing no not-ready warning', async () => {
    await renderPage(stored({ public: false }), [NOT_READY_MESSAGE]);

    const sent = await save();

    expect(sent.access_point.public).toBe(false);
    expect(warningToasts()).toEqual([]);
    expect(toast).toHaveBeenCalledWith('success', 'Agent Surface "orders" saved');
    expect(screen.queryByTestId('surface-save-warnings')).not.toBeInTheDocument();
    expect(toast.mock.calls.some(c => c[0] === 'error')).toBe(false);
  });

  it('never sends access_point_status back', async () => {
    await renderPage({ ...stored({ public: true }), access_point_status: 'ready' });

    const sent = await save();

    expect(sent).not.toHaveProperty('access_point_status');
  });
});

describe('SurfaceDetailPage Access Point readiness notice', () => {
  const notice = () => screen.getByTestId('access-point-notice');

  const renderPage = async (surface: AgentSurface) => {
    jest.spyOn(apiClient, 'getSurface').mockResolvedValue(surface);
    render(
      <MemoryRouter initialEntries={['/surfaces/srf-1']}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<SurfaceDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByTestId('surface-save-button');
  };

  beforeEach(() => {
    jest.restoreAllMocks();
    toast.mockReset();
  });

  it('shows not ready, then save to activate, then clears after the save', async () => {
    const closed = { ...stored({ public: false }), access_point_status: 'not_ready' as const };
    await renderPage(closed);
    expect(notice()).toHaveTextContent(/^not_ready$/);

    fireEvent.click(screen.getByText('Turn on Public access'));
    expect(notice()).toHaveTextContent(/^save_to_activate$/);

    jest
      .spyOn(apiClient, 'updateSurface')
      .mockImplementation(async (_id: string, payload: Partial<AgentSurface>) => ({
        ...closed,
        ...payload,
        access_point_status: 'ready',
      }));
    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() => expect(notice()).toHaveTextContent(/^$/));
  });

  it('shows nothing for a ready surface', async () => {
    await renderPage({
      ...stored({ public: false, caller_authentication: API_KEY_AUTH }),
      access_point_status: 'ready',
    });
    expect(notice()).toHaveTextContent(/^$/);
  });

  it('shows nothing for a surface stored without public', async () => {
    await renderPage(stored({}));
    expect(notice()).toHaveTextContent(/^$/);
  });
});

describe('SurfaceDetailPage API key references', () => {
  let updateSurface: jest.SpyInstance;

  const REVOKED_WARNING =
    'The API key this Identity uses was revoked. Select an active API key of this surface.';

  const withKey = (
    keyId: string,
    references: AgentSurface['api_key_references'],
    extra: Partial<AgentSurface> = {}
  ): AgentSurface =>
    ({
      ...stored({ public: true }),
      access_point: {
        listen_address: 'https://gw.example',
        route: '/agents/orders',
        protocol: 'a2a',
        public: true,
      },
      identity_slots: { protected: { type: 'from_api_key', api_key_id: keyId } },
      api_key_references: references,
      ...extra,
    }) as unknown as AgentSurface;

  const renderPage = async (surface: AgentSurface) => {
    jest.spyOn(apiClient, 'getSurface').mockResolvedValue(surface);
    updateSurface.mockImplementation(async (_id: string, payload: Partial<AgentSurface>) => ({
      ...surface,
      ...payload,
    }));
    render(
      <MemoryRouter initialEntries={['/surfaces/srf-1']}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<SurfaceDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByTestId('surface-save-button');
  };

  const errorToasts = () => toast.mock.calls.filter(c => c[0] === 'error').map(c => c[1]);

  beforeEach(() => {
    jest.restoreAllMocks();
    toast.mockReset();
    updateSurface = jest.spyOn(apiClient, 'updateSurface');
  });

  it('blocks Save on a blocking base key and sends no PUT', async () => {
    await renderPage(
      withKey('atgk_bad', [{ key_id: 'atgk_bad', status: 'revoked', blocking: true }])
    );

    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() => expect(errorToasts()).toEqual([`Identity: ${REVOKED_WARNING}`]));
    expect(updateSurface).not.toHaveBeenCalled();
  });

  it('blocks Save on a blocking key of an inactive variant, naming the variant', async () => {
    await renderPage(
      withKey(
        'atgk_good',
        [
          { key_id: 'atgk_good', status: 'active', blocking: false },
          { key_id: 'atgk_bad', status: 'revoked', blocking: true },
        ],
        {
          variants: [
            {
              id: 'v-beta',
              alias: 'beta',
              name: 'Beta',
              overrides: {
                identity_slots: { protected: { type: 'from_api_key', api_key_id: 'atgk_bad' } },
              },
            },
          ],
        }
      )
    );

    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() =>
      expect(errorToasts()).toEqual([`Variant "Beta" — Identity: ${REVOKED_WARNING}`])
    );
    expect(updateSurface).not.toHaveBeenCalled();
  });

  it('saves with an active key', async () => {
    await renderPage(
      withKey('atgk_good', [{ key_id: 'atgk_good', status: 'active', blocking: false }])
    );

    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() => expect(updateSurface).toHaveBeenCalledTimes(1));
    expect(errorToasts()).toEqual([]);
  });

  it('saves with a key of another surface that does not block', async () => {
    await renderPage(
      withKey('atgk_other', [{ key_id: 'atgk_other', status: 'unavailable', blocking: false }])
    );

    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() => expect(updateSurface).toHaveBeenCalledTimes(1));
    expect(errorToasts()).toEqual([]);
    const sent = updateSurface.mock.calls[0][1] as AgentSurface;
    expect(sent).not.toHaveProperty('api_key_references');
    expect(sent).not.toHaveProperty('serving_status');
  });

  it('blocks Save on a key of another surface that blocks', async () => {
    await renderPage(
      withKey('atgk_other', [{ key_id: 'atgk_other', status: 'unavailable', blocking: true }])
    );

    fireEvent.click(screen.getByTestId('surface-save-button'));

    await waitFor(() =>
      expect(errorToasts()).toEqual([
        'Identity: The API key this Identity uses belongs to another surface. Select an active API key of this surface.',
      ])
    );
    expect(updateSurface).not.toHaveBeenCalled();
  });
});

describe('SurfaceDetailPage serving status', () => {
  const renderPage = async (surface: AgentSurface) => {
    jest.spyOn(apiClient, 'getSurface').mockResolvedValue(surface);
    render(
      <MemoryRouter initialEntries={['/surfaces/srf-1']}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<SurfaceDetailPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByTestId('surface-save-button');
  };

  beforeEach(() => {
    jest.restoreAllMocks();
    toast.mockReset();
  });

  it('says the surface is refusing requests when it is not serving', async () => {
    await renderPage({ ...stored({ public: true }), serving_status: 'not_serving' });

    expect(screen.getByTestId('surface-refusing-requests')).toHaveTextContent(
      'This surface is refusing requests'
    );
  });

  it.each(['serving', 'not_judged', undefined] as const)(
    'shows no refusing notice when serving_status is %s',
    async servingStatus => {
      await renderPage({ ...stored({ public: true }), serving_status: servingStatus });

      expect(screen.queryByTestId('surface-refusing-requests')).toBeNull();
    }
  );
});

describe('SurfaceDetailPage delete', () => {
  const openDeleteDialog = async () => {
    render(
      <MemoryRouter initialEntries={['/surfaces/s1']}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<SurfaceDetailPage />} />
          <Route path="/surfaces" element={<p>Surfaces list</p>} />
        </Routes>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByTestId('surface-delete-button'));
    return screen.getByRole('dialog', { name: 'Delete Surface?' });
  };

  it('asks before deleting, naming the surface, and sends nothing until confirmed', async () => {
    const remove = jest.spyOn(apiClient, 'deleteSurface').mockResolvedValue();

    const dialog = await openDeleteDialog();

    expect(dialog).toHaveTextContent(
      'You are about to permanently delete agent and all associated configuration. This action cannot be undone.'
    );
    expect(dialog).toHaveTextContent('Are you sure you want to continue?');
    expect(within(dialog).getByText('agent').tagName).toBe('STRONG');
    expect(screen.getByTestId('surface-delete-dialog-confirm')).toBeEnabled();
    expect(remove).not.toHaveBeenCalled();
  });

  it('deletes once after Delete surface, then returns to the surfaces list', async () => {
    const remove = jest.spyOn(apiClient, 'deleteSurface').mockResolvedValue();
    await openDeleteDialog();

    fireEvent.click(screen.getByTestId('surface-delete-dialog-confirm'));

    expect(await screen.findByText('Surfaces list')).toBeInTheDocument();
    expect(remove).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledWith('s1');
    expect(showToast).toHaveBeenCalledWith('success', 'Surface "agent" deleted');
  });

  it.each(['Cancel', 'Close'])('%s closes the dialog and deletes nothing', async name => {
    const remove = jest.spyOn(apiClient, 'deleteSurface').mockResolvedValue();
    const dialog = await openDeleteDialog();

    fireEvent.click(within(dialog).getByRole('button', { name }));

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByTestId('surface-delete-button')).toBeEnabled();
    expect(screen.queryByText('Surfaces list')).not.toBeInTheDocument();
    expect(remove).not.toHaveBeenCalled();
  });

  it('disables Delete surface while the delete runs', async () => {
    let finish: () => void = () => {};
    const remove = jest
      .spyOn(apiClient, 'deleteSurface')
      .mockReturnValue(new Promise<void>(resolve => (finish = resolve)));
    await openDeleteDialog();
    const confirm = screen.getByTestId('surface-delete-dialog-confirm');

    fireEvent.click(confirm);
    await waitFor(() => expect(confirm).toBeDisabled());
    fireEvent.click(confirm);
    finish();

    expect(await screen.findByText('Surfaces list')).toBeInTheDocument();
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('shows a failed delete in the error banner and stays on the surface', async () => {
    jest
      .spyOn(apiClient, 'deleteSurface')
      .mockRejectedValue(new Error('Surface store unavailable'));
    await openDeleteDialog();

    fireEvent.click(screen.getByTestId('surface-delete-dialog-confirm'));

    expect(await screen.findByTestId('surface-error-alert')).toHaveTextContent(
      'Surface store unavailable'
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByTestId('surface-delete-button')).toBeEnabled();
    expect(screen.queryByText('Surfaces list')).not.toBeInTheDocument();
    expect(showToast).not.toHaveBeenCalledWith('success', expect.anything());
  });
});
