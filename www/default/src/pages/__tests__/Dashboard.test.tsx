import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../Dashboard';
import { useApp } from '../../context/AppContext';
import { apiClient } from '../../api';

jest.mock('../../context/AppContext', () => ({
  useApp: jest.fn(),
}));

jest.mock('../../api', () => ({
  apiClient: {
    listSurfaces: jest.fn(),
  },
}));

jest.mock('react-chartjs-2', () => ({
  Line: () => <div data-testid="line-chart" />,
  Doughnut: () => <div data-testid="doughnut-chart" />,
  Bar: () => <div data-testid="bar-chart" />,
}));

jest.mock('chart.js', () => ({
  Chart: {
    register: jest.fn(),
  },
  CategoryScale: jest.fn(),
  LinearScale: jest.fn(),
  PointElement: jest.fn(),
  LineElement: jest.fn(),
  Title: jest.fn(),
  Tooltip: jest.fn(),
  Legend: jest.fn(),
  Filler: jest.fn(),
  ArcElement: jest.fn(),
  BarElement: jest.fn(),
}));

const mockedUseApp = useApp as jest.Mock;
const mockedApiClient = apiClient as jest.Mocked<typeof apiClient>;

type DashboardTestContext = {
  state: {
    settings: null;
    isLoading: { dashboard: boolean; settings: boolean };
    error: string | null;
    globalState: { currentBucketSeconds: number };
  };
  actions: {
    setDashboardFilters: jest.Mock;
    setWsSubscription: jest.Mock;
    loadDashboardStats: jest.Mock;
    setDashboardBucketOverride: jest.Mock;
  };
  getCurrentStats: jest.Mock;
};

const makeStats = (channelsCount: number) => ({
  total_identities: 0,
  identities: [],
  channels: Array.from({ length: channelsCount }, (_, i) => ({
    name: `surface-${i + 1}`,
    config_id: `surface-${i + 1}`,
    accept_count: 0,
    deny_count: 0,
    rule_count: 0,
    gateway_faults: 0,
  })),
  metrics: {
    total_connections: 0,
    avg_latency: null,
    avg_request_latency: null,
    avg_response_latency: null,
    avg_pipe_gateway_processing_ms: null,
    avg_pipe_target_processing_ms: null,
    connections_window_minutes: 60,
    latency_window_minutes: 60,
    time_series: [],
    latency_time_series: [],
    channel_stats: [],
    identity_channel_stats: [],
    pipe_stats: [],
  },
});

const makeContextValue = (
  channelsCount: number,
  error: DashboardTestContext['state']['error'] = null
): DashboardTestContext => {
  const stats = makeStats(channelsCount);
  return {
    state: {
      settings: null,
      isLoading: { dashboard: false, settings: false },
      error,
      globalState: {
        currentBucketSeconds: 30,
      },
    },
    actions: {
      setDashboardFilters: jest.fn(),
      setWsSubscription: jest.fn(),
      loadDashboardStats: jest.fn(),
      setDashboardBucketOverride: jest.fn(),
    },
    getCurrentStats: jest.fn(() => stats),
  };
};

describe('Dashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedApiClient.listSurfaces.mockResolvedValue([] as any);
  });

  it('forces a dashboard stats refresh on mount', () => {
    const ctx = makeContextValue(0);
    mockedUseApp.mockReturnValue(ctx);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    expect(ctx.actions.loadDashboardStats).toHaveBeenCalledWith(true);
  });

  it('shows created surface count and hides create-surface CTA when configured surfaces exist', async () => {
    const ctx = makeContextValue(0);
    mockedApiClient.listSurfaces.mockResolvedValue([
      {
        surface_id: 'surface-1',
        name: 'Surface 1',
        description: '',
        tags: [],
        status: 'active',
        access_point: {
          protocol: 'a2a',
          route: '/rpc',
          policy_id: '',
          supports_streaming: false,
          mcp_tool_policies: null,
        },
        target: {
          endpoint: 'https://example.com',
          timeout: 60,
          auth: null,
          headers: [],
        },
        transit_points: [],
      } as any,
    ]);
    mockedUseApp.mockReturnValue(ctx);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('dashboard-stat-channels')).toHaveTextContent('1');
    });
    expect(screen.queryByRole('button', { name: /create agent surface/i })).not.toBeInTheDocument();
  });

  it('reloads configured surface count from the bucket refresh path', async () => {
    const ctx = makeContextValue(0);
    mockedApiClient.listSurfaces.mockResolvedValueOnce([] as any).mockResolvedValueOnce([
      {
        surface_id: 'surface-1',
        name: 'Surface 1',
        description: '',
        tags: [],
        status: 'active',
        access_point: {
          protocol: 'a2a',
          route: '/rpc',
          policy_id: '',
          supports_streaming: false,
          mcp_tool_policies: null,
        },
        target: {
          endpoint: 'https://example.com',
          timeout: 60,
          auth: null,
          headers: [],
        },
        transit_points: [],
      } as any,
    ]);
    mockedUseApp.mockReturnValue(ctx);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => expect(mockedApiClient.listSurfaces).toHaveBeenCalledTimes(1));

    fireEvent.change(
      screen.getByLabelText('Select time interval for aggregated connections chart'),
      { target: { value: '60' } }
    );

    await waitFor(() => expect(mockedApiClient.listSurfaces).toHaveBeenCalledTimes(2));

    expect(screen.getByTestId('dashboard-stat-channels')).toHaveTextContent('1');
  });

  it('reloads configured surface count from the error retry path', async () => {
    const ctx = makeContextValue(0, 'Initial load failed');
    mockedUseApp.mockReturnValue(ctx);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => expect(mockedApiClient.listSurfaces).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: /try again/i }));

    await waitFor(() => expect(mockedApiClient.listSurfaces).toHaveBeenCalledTimes(2));

    expect(ctx.actions.loadDashboardStats).toHaveBeenLastCalledWith();
  });
});
