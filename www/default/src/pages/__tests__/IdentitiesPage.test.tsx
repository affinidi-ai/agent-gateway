import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import IdentitiesPage from '../IdentitiesPage';
import { AppContext } from '../../context/AppContext';
import { MemoryRouter } from 'react-router-dom';
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
});
