import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient, type AgentSurface } from '../../../api';
import {
  accessPointStatus,
  chooseAccessPointNotice,
  savedAccessPointStatus,
  type AccessPointNotice,
} from '../elements/access-point/readiness';
import AccessPointPanel from '../elements/access-point/AccessPointPanel';
import SurfaceFormShell, { type SurfaceFormShellProps } from '../SurfaceFormShell';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../SurfaceMetaContext';
import type { ConfigPanelProps } from '../elements/types';
import type { CanvasNode } from '../SurfaceCanvas';

jest.mock('../../../api', () => ({
  ...jest.requireActual('../../../api'),
  apiClient: { get: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../SurfaceCanvas', () => ({ __esModule: true, default: () => null }));
jest.mock('../NodeConfigPanel', () => ({ __esModule: true, default: () => null }));
jest.mock('../SurfaceVariantsWidget', () => ({ __esModule: true, default: () => null }));
jest.mock('../elements/trust-check/MigratedTrustChecksSummary', () => ({
  __esModule: true,
  default: () => null,
}));
jest.mock('../../../utils/featureFlags', () => ({
  useAgentPayFlag: () => ({ enabled: false, loaded: true }),
}));

const NOT_READY = 'Not ready for external access';
const SAVE_TO_ACTIVATE = 'Not ready for external access. Save to activate.';
const ENTRY_URL = 'https://gw.example.com/agents/helpdesk/v1';
const AP_CONFIG = {
  listen_address: 'https://gw.example.com',
  route_prefix: '/agents',
  route_suffix: 'helpdesk/v1',
  route: '/agents/helpdesk/v1',
};
const API_KEY_AUTH = {
  methods: [{ type: 'api_key', extraction: { source: 'http_header', field: 'X-Api-Key' } }],
};

beforeEach(() => {
  jest.clearAllMocks();
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve(
          url === '/api/v1/config/surface-routing'
            ? {
                available_listen_addresses: ['https://gw.example.com'],
                available_outbound_listen_addresses: [],
                channel_path_prefix: [{ id: 'agents', name: 'agents', prefix: '/agents' }],
              }
            : []
        ),
    })
  );
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
});

describe('accessPointStatus', () => {
  it('is not ready for a closed Access Point without caller authentication', () => {
    expect(accessPointStatus({ access_point: { public: false } })).toBe('not_ready');
    expect(
      accessPointStatus({ access_point: { public: false, caller_authentication: { methods: [] } } })
    ).toBe('not_ready');
  });

  it('is ready with a caller authentication method or an MCP resource token', () => {
    expect(
      accessPointStatus({ access_point: { public: false, caller_authentication: API_KEY_AUTH } })
    ).toBe('ready');
    expect(
      accessPointStatus({ access_point: { public: false }, mcp_http: { authorization: {} } })
    ).toBe('ready');
  });

  it('is always ready for a public or a legacy Access Point', () => {
    expect(accessPointStatus({ access_point: { public: true } })).toBe('ready');
    expect(accessPointStatus({ access_point: {} })).toBe('ready');
  });

  it('treats a new surface without public as closed', () => {
    expect(accessPointStatus({ access_point: {} }, { isNew: true })).toBe('not_ready');
    expect(accessPointStatus({ access_point: { public: true } }, { isNew: true })).toBe('ready');
  });
});

describe('chooseAccessPointNotice', () => {
  it('uses the draft for a new surface', () => {
    expect(chooseAccessPointNotice(null, 'not_ready')).toBe('not_ready');
    expect(chooseAccessPointNotice(null, 'ready')).toBeNull();
  });

  it('uses the saved state, asking to save when the draft would be ready', () => {
    expect(chooseAccessPointNotice('not_ready', 'not_ready')).toBe('not_ready');
    expect(chooseAccessPointNotice('not_ready', 'ready')).toBe('save_to_activate');
    expect(chooseAccessPointNotice('ready', 'not_ready')).toBeNull();
    expect(chooseAccessPointNotice('ready', 'ready')).toBeNull();
  });
});

describe('savedAccessPointStatus', () => {
  const surface = {
    access_point: { public: false, caller_authentication: API_KEY_AUTH },
    access_point_status: 'ready',
    variants: [
      {
        id: 'v1',
        alias: 'beta',
        name: 'Beta',
        overrides: { complete: true, access_point: {} },
      },
    ],
  } as unknown as AgentSurface;

  it("uses the gateway's status for the base surface", () => {
    expect(savedAccessPointStatus(surface, null)).toBe('ready');
    expect(savedAccessPointStatus({ ...surface, access_point_status: 'not_ready' }, null)).toBe(
      'not_ready'
    );
  });

  it('resolves the stored variant over the surface', () => {
    expect(savedAccessPointStatus(surface, 'v1')).toBe('not_ready');
  });
});

const meta = (notice: AccessPointNotice | null, extra: Partial<SurfaceMetaValue> = {}) =>
  ({
    accessPointNotice: notice,
    onConfigureAuthentication: jest.fn(),
    readOnly: false,
    ...extra,
  }) as unknown as SurfaceMetaValue;

describe('Access Point panel under the URL', () => {
  const renderPanel = (value: SurfaceMetaValue) =>
    render(
      <SurfaceMetaProvider value={value}>
        <AccessPointPanel
          {...({
            node: { id: 'access-point', type: 'access-point', label: '', configured: true },
            config: AP_CONFIG,
            updateField: jest.fn(),
            updateFields: jest.fn(),
            protocol: 'mcp',
            allNodes: [],
          } as unknown as ConfigPanelProps)}
        />
      </SurfaceMetaProvider>
    );

  it('shows Public access under the URL, keeps the URL copyable, and leaves not ready to the canvas', async () => {
    renderPanel(meta('not_ready'));

    const banner = screen.getByTestId('access-point-entry-point-url');
    await waitFor(() => expect(banner).toHaveTextContent(ENTRY_URL));
    expect(screen.getByTestId('access-point-entry-point-url-copy-button')).toBeInTheDocument();
    expect(banner).toHaveClass('alert-success');

    const toggle = screen.getByTestId('access-point-public-switch');
    expect(banner.compareDocumentPosition(toggle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByText(NOT_READY)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Configure Authentication' })
    ).not.toBeInTheDocument();
  });

  it('shows no save-to-activate notice either', () => {
    renderPanel(meta('save_to_activate'));
    expect(screen.queryByText(SAVE_TO_ACTIVATE)).not.toBeInTheDocument();
  });
});

describe('Canvas URL readiness notice and Configure Authentication', () => {
  const apNode = {
    id: 'access-point',
    type: 'access-point',
    label: 'Access Point',
    configured: true,
    config: AP_CONFIG,
  } as unknown as CanvasNode;

  const renderShell = (notice: AccessPointNotice | null) => {
    const builder = {
      state: { nodes: [apNode], selectedNodeId: null, surfaceSize: { w: 800, h: 600 } },
      handleNodeClick: jest.fn(),
      commit: jest.fn(),
      setMultiSelection: jest.fn(),
      multiSelectedIds: [],
    };
    const setActiveTab = jest.fn();
    const noop = jest.fn();
    const props = {
      mode: 'edit',
      canEdit: true,
      builder,
      meta: {
        name: 'orders',
        description: '',
        tagsCsv: '',
        status: 'active',
        protocol: 'mcp',
        publishToDid: false,
        terminateTraceId: false,
        issuerId: '',
        didwebvh: { enabled: false },
      },
      setMeta: new Proxy({}, { get: () => noop }),
      jsonOverride: null,
      setJsonOverride: noop,
      jsonError: null,
      setJsonError: noop,
      configEditorValue: '{}',
      activeTab: 'surface',
      setActiveTab,
      editorTabNodeId: null,
      onOpenFullscreenEditor: noop,
      onCloseFullscreenEditor: noop,
      surfacePolicyLoadState: { status: 'loaded', ids: new Set<string>() },
      accessPointNotice: notice,
    } as unknown as SurfaceFormShellProps;
    render(<SurfaceFormShell {...props} />);
    return { builder, setActiveTab };
  };

  it('shows not ready under the canvas URL, which stays copyable', () => {
    renderShell('not_ready');
    const banner = screen.getByTestId('surface-entry-point-url');
    expect(banner).toHaveTextContent(ENTRY_URL);
    expect(screen.getByTestId('surface-entry-point-url-copy-button')).toBeInTheDocument();
    const notice = screen.getByTestId('surface-access-point-readiness');
    expect(notice).toHaveTextContent(NOT_READY);
    expect(banner.compareDocumentPosition(notice) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('asks to save without the action', () => {
    renderShell('save_to_activate');
    const notice = screen.getByTestId('surface-access-point-readiness');
    expect(notice).toHaveTextContent(SAVE_TO_ACTIVATE);
    expect(within(notice).queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows nothing under the canvas URL while ready', () => {
    renderShell(null);
    expect(screen.getByTestId('surface-entry-point-url')).toHaveTextContent(ENTRY_URL);
    expect(screen.queryByTestId('surface-access-point-readiness')).not.toBeInTheDocument();
  });

  it('selects the Access Point and highlights the Caller Context in the palette', () => {
    const { builder, setActiveTab } = renderShell('not_ready');
    expect(screen.queryByTestId('palette-item-caller-auth')).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByTestId('surface-access-point-readiness-configure-authentication-button')
    );

    expect(setActiveTab).toHaveBeenCalledWith('surface');
    expect(builder.handleNodeClick).toHaveBeenCalledWith('access-point');
    expect(screen.getByTestId('palette-item-caller-auth')).toHaveClass('palette-item--highlight');
  });
});
