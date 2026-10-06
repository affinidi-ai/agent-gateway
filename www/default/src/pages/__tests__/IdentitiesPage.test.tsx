import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import IdentitiesPage from '../IdentitiesPage';
import { AppContext } from '../../context/AppContext';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';

// Mock the API client
jest.mock('../../api', () => ({
  apiClient: {
    getIdentityTrustScore: jest.fn(),
    getIdentityVersionHistory: jest.fn(),
    createDidWebVhIdentity: jest.fn(),
    listDidWebVhIdentities: jest.fn().mockResolvedValue({ identities: [] }),
  },
}));

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: jest.fn(),
}));

// Mock chart.js
jest.mock('react-chartjs-2', () => ({
  Radar: () => <div data-testid="radar-chart" />,
}));

jest.mock('chart.js', () => ({
  Chart: {
    register: jest.fn(),
  },
  RadialLinearScale: jest.fn(),
  PointElement: jest.fn(),
  LineElement: jest.fn(),
  Filler: jest.fn(),
  Tooltip: jest.fn(),
  Legend: jest.fn(),
}));

// Mock utils
jest.mock('../../utils/stringUtils', () => ({
  formatDateTime: jest.fn(date => `Formatted: ${date}`),
  timeAgo: jest.fn(date => '2 days ago'),
  topAndTail: jest.fn((str, _top, _tail) => str),
}));

const mockIdentities = [
  {
    id: 'identity-1',
    did: 'did:webvh:zScid1:example.com:agents:gpt4',
    uuid: 'uuid-1',
    scid: 'scid-1',
    uai: 'uai-1',
    version: 3,
    status: 'active',
    controller: 'did:web:example.com:controller',
    created_at: '2026-02-01T10:00:00Z',
    updated_at: '2026-02-13T10:00:00Z',
    trust_score: 0.85,
    trust_components: {
      genesis: 0.92,
      behavioral: 0.78,
      operational: 0.85,
      attestation: 0.82,
      history: 0.9,
    },
    has_tee: true,
    has_cloud_attestation: false,
  },
  {
    id: 'identity-2',
    did: 'did:webvh:zScid2:example.com:agents:claude',
    uuid: 'uuid-2',
    version: 1,
    status: 'active',
    controller: 'did:web:example.com:controller',
    created_at: '2026-02-10T10:00:00Z',
    updated_at: '2026-02-10T10:00:00Z',
    trust_score: 0.45,
    has_tee: false,
    has_cloud: true,
    has_cloud_attestation: true,
  },
];

const mockAppContext: any = {
  state: {
    theme: 'light' as const,
    sidebarCollapsed: false,
    globalState: {
      stats: {
        identities: mockIdentities,
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
        total_identities: mockIdentities.length,
        ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
        metrics: {
          total_connections: 0,
          avg_latency: null,
          avg_request_latency: null,
          avg_response_latency: null,
          connections_window_minutes: 5,
          latency_window_minutes: 5,
          time_series: [],
          channel_stats: [],
        },
        proxy_info: [],
        unread_count: 0,
      },
      lastSyncTimestamp: Date.now(),
      currentBucketSeconds: 60,
    },
    filteredState: {
      stats: null,
      lastSyncTimestamp: null,
      currentBucketSeconds: null,
    },
    activeView: 'global' as const,
    settings: null,
    dashboardBucketOverride: null,
    dashboardFilters: null,
    wsStatus: 'disconnected' as const,
    wsConnection: null,
    isLoading: {
      dashboard: false,
      settings: false,
    },
    error: null,
  },
  dispatch: jest.fn(),
  getCurrentStats: jest.fn(() => ({
    identities: mockIdentities,
    channels: [] as any[],
    gateways: [] as any[],
    pipes: [] as any[],
    total_identities: mockIdentities.length,
    ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
    metrics: {
      total_connections: 0,
      avg_latency: null as any,
      avg_request_latency: null as any,
      avg_response_latency: null as any,
      connections_window_minutes: 5,
      latency_window_minutes: 5,
      time_series: [] as any[],
      channel_stats: [] as any[],
    },
    proxy_info: [] as any[],
    unread_count: 0,
  })),
  actions: {
    loadSettings: jest.fn(),
    updateSettings: jest.fn(),
    toggleTheme: jest.fn(),
    toggleSidebar: jest.fn(),
    setError: jest.fn(),
    refreshDashboard: jest.fn(),
    refreshDashboardWithFilters: jest.fn(),
    clearDashboardFilters: jest.fn(),
    setDashboardBucketOverride: jest.fn(),
    connectWebSocket: jest.fn(),
    disconnectWebSocket: jest.fn(),
    setWsSubscription: jest.fn(),
  },
};

describe('IdentitiesPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Re-apply stringUtils mock implementations reset by resetMocks: true
    const stringUtils = require('../../utils/stringUtils');
    stringUtils.formatDateTime.mockImplementation((date: string) => `Formatted: ${date}`);
    stringUtils.timeAgo.mockImplementation(() => '2 days ago');
    stringUtils.topAndTail.mockImplementation((str: string) => str);
    (usePermissions as jest.Mock).mockReturnValue({
      permissions: { 'issuers.view': true },
      loading: false,
      error: null,
      refetchPermissions: jest.fn(),
      hasPermission: jest.fn((permission: string) => permission === 'issuers.view'),
    });
    // Re-apply mock implementations cleared by jest.clearAllMocks()
    (mockAppContext.getCurrentStats as jest.Mock).mockImplementation(() => ({
      identities: mockIdentities,
      channels: [] as any[],
      gateways: [] as any[],
      pipes: [] as any[],
      total_identities: mockIdentities.length,
      ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
      metrics: {
        total_connections: 0,
        avg_latency: null as any,
        avg_request_latency: null as any,
        avg_response_latency: null as any,
        connections_window_minutes: 5,
        latency_window_minutes: 5,
        time_series: [] as any[],
        channel_stats: [] as any[],
      },
      proxy_info: [] as any[],
      unread_count: 0,
    }));
    (apiClient.listDidWebVhIdentities as jest.Mock).mockResolvedValue({ identities: [] });
  });

  it('renders identities list', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/did:webvh:zScid1:example\.com:agents:gpt4/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/did:webvh:zScid2:example\.com:agents:claude/i)).toBeInTheDocument();
  });

  it('displays trust score progress bars', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      const progressBars = screen.getAllByRole('progressbar');
      expect(progressBars.length).toBeGreaterThan(0);
    });
  });

  it('displays attestation icons for TEE', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTitle(/TEE Enabled/i)).toBeInTheDocument();
    });
  });

  it('displays attestation icons for Cloud', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTitle(/Cloud Attestation/i)).toBeInTheDocument();
    });
  });

  it('opens trust score modal when button clicked', async () => {
    (apiClient.getIdentityTrustScore as jest.Mock).mockResolvedValue({
      did: mockIdentities[0].did,
      overall_score: 0.85,
      components: mockIdentities[0].trust_components,
      computed_at: '2026-02-13T10:00:00Z',
      version: 3,
      has_tee: true,
      has_cloud_attestation: false,
    });

    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/did:webvh:zScid1:example\.com:agents:gpt4/i)).toBeInTheDocument();
    });

    const trustScoreButtons = screen.getAllByTitle(/View trust score/i);
    fireEvent.click(trustScoreButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Trust Score Analysis')).toBeInTheDocument();
    });
  });

  it('opens version history modal when button clicked', async () => {
    (apiClient.getIdentityVersionHistory as jest.Mock).mockResolvedValue([
      {
        version: 1,
        timestamp: '2026-02-01T10:00:00Z',
        operation: 'birth',
        signer: 'did:web:example.com:admin',
        hash: 'abc123',
        changes: ['Initial creation'],
      },
    ]);

    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/did:webvh:zScid1:example\.com:agents:gpt4/i)).toBeInTheDocument();
    });

    const historyButtons = screen.getAllByTitle(/View version history/i);
    fireEvent.click(historyButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Version History')).toBeInTheDocument();
    });
  });

  it('displays correct trust score color for high score', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      const progressBars = screen.getAllByRole('progressbar');
      const highScoreBar = progressBars.find(bar => bar.getAttribute('aria-valuenow') === '85');
      expect(highScoreBar).toHaveClass('bg-success');
    });
  });

  it('displays correct trust score color for low score', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      const progressBars = screen.getAllByRole('progressbar');
      const lowScoreBar = progressBars.find(bar => bar.getAttribute('aria-valuenow') === '45');
      expect(lowScoreBar).toHaveClass('bg-warning');
    });
  });

  it('displays version badges', async () => {
    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('v3')).toBeInTheDocument();
    });
    expect(screen.getByText('v1')).toBeInTheDocument();
  });

  it('handles empty identities list', async () => {
    const emptyContext = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: [] as any[],
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={emptyContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      // Component shows empty state message when no identities are present
      expect(screen.getByText(/No agent identities yet/i)).toBeInTheDocument();
    });
  });

  it('handles API error gracefully', async () => {
    const errorContext = {
      ...mockAppContext,
      state: {
        ...mockAppContext.state,
        error: 'API Error',
      },
      getCurrentStats: jest.fn(() => null as any),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={errorContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    // Component renders even with errors.
    expect(screen.getByRole('tab', { name: /Agent Identities/i })).toBeInTheDocument();
  });

  it('copies identity link to clipboard when copy button clicked', async () => {
    // Mock clipboard API
    Object.assign(navigator, {
      clipboard: {
        writeText: jest.fn(() => Promise.resolve()),
      },
    });

    render(
      <MemoryRouter>
        <AppContext.Provider value={mockAppContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/did:webvh:zScid1:example\.com:agents:gpt4/i)).toBeInTheDocument();
    });

    const copyButtons = screen.getAllByTitle(/Copy link/i);
    fireEvent.click(copyButtons[0]);

    await waitFor(() => {
      // URL must follow did:webvh DID-to-HTTPS transformation (spec §3.4):
      // did:webvh:zScid1:example.com:agents:gpt4 → <origin>/agents/gpt4/did.jsonl
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        expect.stringContaining('/agents/gpt4/did.jsonl')
      );
    });
  });

  it('does not show trust score button for identity without trust score', async () => {
    const identitiesWithoutScore = [
      {
        ...mockIdentities[0],
        trust_score: undefined as any,
        trust_components: undefined as any,
      },
    ];
    const contextWithoutScore = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: identitiesWithoutScore,
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={contextWithoutScore}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      const trustScoreButtons = screen.queryAllByTitle(/View trust score/i);
      expect(trustScoreButtons.length).toBe(0);
    });
  });

  it('does not show history button for identity without uuid', async () => {
    const identitiesWithoutUuid = [
      {
        ...mockIdentities[0],
        uuid: undefined as any,
      },
    ];
    const contextWithoutUuid = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: identitiesWithoutUuid,
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={contextWithoutUuid}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      const historyButtons = screen.queryAllByTitle(/View version history/i);
      expect(historyButtons.length).toBe(0);
    });
  });

  // === Identity Page Migration Display Tests ===
  // did:web identity must render without SCID and without trust score button.
  it('did_web_identity_rendered_without_scid_and_trust_score', async () => {
    const didWebIdentity = {
      id: 'identity-web',
      did: 'did:web:example.com:agents:legacy',
      // No scid, no uuid, no trust_score
      status: 'active',
      controller: 'did:web:example.com:controller',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      has_tee: false,
      has_cloud_attestation: false,
    };
    const contextWithWebDid = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: [didWebIdentity],
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
        total_identities: 1,
        ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
        metrics: {
          total_connections: 0,
          avg_latency: null as any,
          avg_request_latency: null as any,
          avg_response_latency: null as any,
          connections_window_minutes: 5,
          latency_window_minutes: 5,
          time_series: [] as any[],
          channel_stats: [] as any[],
        },
        proxy_info: [] as any[],
        unread_count: 0,
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={contextWithWebDid}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      // The did:web identity must appear in the table
      expect(screen.getByText(/did:web:example\.com:agents:legacy/i)).toBeInTheDocument();
    });

    expect(screen.queryAllByTitle(/View trust score/i)).toHaveLength(0);
    expect(screen.queryAllByTitle(/View version history/i)).toHaveLength(0);
  });

  // did:webvh identity must render with SCID, version badge, and action buttons.
  it('did_webvh_identity_rendered_with_scid_version_and_buttons', async () => {
    const didWebvhIdentity = {
      id: 'identity-webvh',
      did: 'did:webvh:z6Mkscid001:example.com:agents:modern',
      uuid: 'uuid-webvh',
      scid: 'z6Mkscid001',
      version: 5,
      status: 'active',
      controller: 'did:web:example.com:controller',
      created_at: '2026-02-01T00:00:00Z',
      updated_at: '2026-02-20T00:00:00Z',
      trust_score: 0.92,
      trust_components: {
        genesis: 0.95,
        behavioral: 0.88,
        operational: 0.93,
        attestation: 0.9,
        history: 0.94,
      },
      has_tee: true,
      has_cloud_attestation: false,
    };
    const contextWithWebvhDid = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: [didWebvhIdentity],
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
        total_identities: 1,
        ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
        metrics: {
          total_connections: 0,
          avg_latency: null as any,
          avg_request_latency: null as any,
          avg_response_latency: null as any,
          connections_window_minutes: 5,
          latency_window_minutes: 5,
          time_series: [] as any[],
          channel_stats: [] as any[],
        },
        proxy_info: [] as any[],
        unread_count: 0,
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={contextWithWebvhDid}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      // The did:webvh DID must appear
      expect(
        screen.getByText(/did:webvh:z6Mkscid001:example\.com:agents:modern/i)
      ).toBeInTheDocument();
    });

    expect(screen.getByText('v5')).toBeInTheDocument();
    expect(screen.queryAllByTitle(/View trust score/i).length).toBeGreaterThan(0);
    expect(screen.queryAllByTitle(/View version history/i).length).toBeGreaterThan(0);
  });

  // mixed list of did:web and did:webvh must render correctly without cross-contamination.
  it('mixed_list_renders_both_types_correctly_without_cross_contamination', async () => {
    const didWebIdentity = {
      id: 'identity-web',
      did: 'did:web:example.com:agents:legacy',
      // No scid, no version, no trust_score
      status: 'active',
      controller: 'did:web:example.com:controller',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      has_tee: false,
      has_cloud_attestation: false,
    };
    const didWebvhIdentity = {
      id: 'identity-webvh',
      did: 'did:webvh:z6Mkscid002:example.com:agents:modern',
      uuid: 'uuid-webvh-mixed',
      scid: 'z6Mkscid002',
      version: 2,
      status: 'active',
      controller: 'did:web:example.com:controller',
      created_at: '2026-02-01T00:00:00Z',
      updated_at: '2026-02-15T00:00:00Z',
      trust_score: 0.75,
      trust_components: {
        genesis: 0.8,
        behavioral: 0.7,
        operational: 0.75,
        attestation: 0.72,
        history: 0.78,
      },
      has_tee: false,
      has_cloud_attestation: true,
    };
    const mixedContext = {
      ...mockAppContext,
      getCurrentStats: jest.fn(() => ({
        identities: [didWebIdentity, didWebvhIdentity],
        channels: [] as any[],
        gateways: [] as any[],
        pipes: [] as any[],
        total_identities: 2,
        ports: { proxy_channels: [] as any[], identity_http: 8446, identity_https: 8443 },
        metrics: {
          total_connections: 0,
          avg_latency: null as any,
          avg_request_latency: null as any,
          avg_response_latency: null as any,
          connections_window_minutes: 5,
          latency_window_minutes: 5,
          time_series: [] as any[],
          channel_stats: [] as any[],
        },
        proxy_info: [] as any[],
        unread_count: 0,
      })),
    };

    render(
      <MemoryRouter>
        <AppContext.Provider value={mixedContext}>
          <IdentitiesPage />
        </AppContext.Provider>
      </MemoryRouter>
    );

    await waitFor(() => {
      // Both DIDs must be visible
      expect(screen.getByText(/did:web:example\.com:agents:legacy/i)).toBeInTheDocument();
    });
    expect(
      screen.getByText(/did:webvh:z6Mkscid002:example\.com:agents:modern/i)
    ).toBeInTheDocument();

    expect(screen.queryAllByTitle(/View trust score/i)).toHaveLength(1);
    expect(screen.queryAllByTitle(/View version history/i)).toHaveLength(1);
    expect(screen.getByText('v2')).toBeInTheDocument();
  });

  describe('naming metadata', () => {
    const statsWith = (identities: any[], channels: any[] = []) => ({
      ...mockAppContext.getCurrentStats(),
      identities,
      channels,
      total_identities: identities.length,
    });

    const renderWithStats = (identities: any[], channels: any[] = []) => {
      const stats = statsWith(identities, channels);
      const context = { ...mockAppContext, getCurrentStats: jest.fn(() => stats) };
      return render(
        <MemoryRouter initialEntries={['/identities']}>
          <AppContext.Provider value={context}>
            <Routes>
              <Route path="/identities" element={<IdentitiesPage />} />
              <Route path="/identities/:did" element={<IdentitiesPage />} />
              <Route path="/surfaces/:id" element={<div data-testid="surface-builder" />} />
            </Routes>
          </AppContext.Provider>
        </MemoryRouter>
      );
    };

    const managedOld = {
      did: 'did:key:managed-old',
      identity_hash: 'hash-old',
      created_at: '2026-01-01T00:00:00Z',
      last_used_at: '2026-01-05T00:00:00Z',
      is_local: true,
      origin: 'managed',
      display_name: 'OXYGEN',
      display_name_source: 'surface_name',
      surface_id: 'surface-1',
      surface_name: 'OXYGEN',
      credential_principal: { kind: 'certificate', id: 'cert-1', name: 'NITROGEN' },
      group_key: 'surface:surface-1',
    };
    const managedNew = {
      ...managedOld,
      did: 'did:key:managed-new',
      identity_hash: 'hash-new',
      created_at: '2026-02-01T00:00:00Z',
      last_used_at: '2026-02-05T00:00:00Z',
    };
    const callerNamed = {
      did: 'did:web:caller.example',
      identity_hash: 'hash-caller',
      created_at: '2026-01-01T00:00:00Z',
      is_local: false,
      origin: 'external_caller',
      display_name: 'acme.com/@billing',
      display_name_source: 'agent_name',
      display_name_verified: true,
      group_key: 'did:did:web:caller.example',
    };
    const callerUnnamed = {
      did: 'did:web:anon.example',
      identity_hash: 'hash-anon',
      created_at: '2026-01-01T00:00:00Z',
      is_local: false,
      origin: 'external_caller',
      group_key: 'did:did:web:anon.example',
    };
    const callerPending = {
      did: 'did:web:pending.example',
      identity_hash: 'hash-pending',
      created_at: '2026-01-01T00:00:00Z',
      is_local: false,
      origin: 'external_caller',
      display_name_pending: true,
      group_key: 'did:did:web:pending.example',
    };

    it('groups managed identities into one row with the latest as primary', async () => {
      renderWithStats([managedOld, managedNew, callerNamed]);

      const row = await screen.findByTestId('identities-row-surface:surface-1');
      expect(within(row).getByTitle('did:key:managed-new')).toBeInTheDocument();
      expect(screen.queryByTitle('did:key:managed-old')).not.toBeInTheDocument();
      expect(within(row).getByTestId('identities-origin-managed')).toHaveTextContent(
        'Managed Agent'
      );
      expect(within(row).getByTestId('identities-credential-principal')).toHaveTextContent(
        'NITROGEN'
      );
      expect(screen.getAllByTestId(/^identities-row-/)).toHaveLength(2);
      expect(
        within(screen.getByTestId('identities-row-did:did:web:caller.example')).getByTestId(
          'identities-origin-external_caller'
        )
      ).toBeInTheDocument();
    });

    it('shows the change log of the surface group when expanded', async () => {
      renderWithStats([managedOld, managedNew]);

      fireEvent.click(await screen.findByTestId('identities-row-surface:surface-1'));
      fireEvent.click(screen.getByTestId('identities-change-log-toggle'));

      const entries = screen.getAllByTestId('identities-change-log-entry');
      expect(entries).toHaveLength(1);
      expect(within(entries[0]).getByTitle('did:key:managed-old')).toBeInTheDocument();
    });

    it('prefers the live surface name and deep links to the surface', async () => {
      renderWithStats([managedNew], [{ config_id: 'surface-1', name: 'OXYGEN renamed' }]);

      const link = await screen.findByTestId('identities-surface-link');
      expect(link).toHaveTextContent('OXYGEN renamed');
      expect(screen.getByTestId('identities-name')).toHaveTextContent('OXYGEN renamed');

      fireEvent.click(link);
      expect(await screen.findByTestId('surface-builder')).toBeInTheDocument();
    });

    it('filters to unnamed identities, excluding names still resolving', async () => {
      renderWithStats([managedNew, callerNamed, callerUnnamed, callerPending]);

      const filter = await screen.findByTestId('identities-unnamed-filter-button');
      expect(filter).toHaveTextContent('Unnamed only (1)');
      expect(filter).toHaveAttribute('aria-pressed', 'false');
      expect(screen.getAllByTestId(/^identities-row-/)).toHaveLength(4);
      expect(
        within(screen.getByTestId('identities-row-did:did:web:pending.example')).getByTestId(
          'identities-name-pending'
        )
      ).toHaveTextContent('resolving…');

      fireEvent.click(filter);

      expect(filter).toHaveAttribute('aria-pressed', 'true');
      const rows = screen.getAllByTestId(/^identities-row-/);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveAttribute('data-testid', 'identities-row-did:did:web:anon.example');
      expect(within(rows[0]).queryByTestId('identities-name')).not.toBeInTheDocument();
      expect(within(rows[0]).getByTitle('did:web:anon.example')).toBeInTheDocument();
      expect(within(rows[0]).queryByText('No name')).not.toBeInTheDocument();

      fireEvent.click(filter);
      expect(screen.getAllByTestId(/^identities-row-/)).toHaveLength(4);
    });

    it('looks as before when the backend sends no naming fields', async () => {
      renderWithStats([
        { did: 'did:key:legacy-a', identity_hash: 'a', created_at: '2026-01-01T00:00:00Z' },
        { did: 'did:key:legacy-b', identity_hash: 'b', created_at: '2026-01-02T00:00:00Z' },
      ]);

      expect(await screen.findAllByTestId(/^identities-row-/)).toHaveLength(2);
      expect(screen.getByRole('columnheader', { name: 'DID' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Origin' })).toBeInTheDocument();
      expect(screen.queryByRole('columnheader', { name: 'Status' })).not.toBeInTheDocument();
      expect(screen.queryByTestId('identities-unnamed-filter-button')).not.toBeInTheDocument();
      expect(screen.queryByTestId('identities-name')).not.toBeInTheDocument();
      expect(screen.queryByText('No name')).not.toBeInTheDocument();
      expect(screen.queryByTestId(/^identities-origin-/)).not.toBeInTheDocument();
    });

    it('expands rows independently', async () => {
      renderWithStats([managedNew, callerNamed]);

      const rowA = await screen.findByTestId('identities-row-surface:surface-1');
      const rowB = screen.getByTestId('identities-row-did:did:web:caller.example');

      fireEvent.click(rowA);
      fireEvent.click(rowB);
      expect(rowA).toHaveAttribute('aria-expanded', 'true');
      expect(rowB).toHaveAttribute('aria-expanded', 'true');
      expect(screen.getAllByText('Identity Hash:')).toHaveLength(2);

      fireEvent.click(rowA);
      expect(rowA).toHaveAttribute('aria-expanded', 'false');
      expect(rowB).toHaveAttribute('aria-expanded', 'true');
      expect(screen.getAllByText('Identity Hash:')).toHaveLength(1);
      expect(screen.getByText('hash-caller')).toBeInTheDocument();
    });
  });
});
