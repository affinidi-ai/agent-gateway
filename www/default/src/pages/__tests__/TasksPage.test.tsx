import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import TasksPage from '../TasksPage';
import { useApp } from '../../context/AppContext';
import { apiClient } from '../../api';
import { useFabricResolver } from '../../utils/useFabricResolver';

jest.mock('../../context/AppContext', () => ({
  useApp: jest.fn(),
}));

jest.mock('../../api', () => ({
  apiClient: {
    listSurfaces: jest.fn(),
  },
}));

jest.mock('../../utils/useFabricResolver', () => ({
  useFabricResolver: jest.fn(),
}));

const mockedUseApp = useApp as jest.Mock;
const mockedApiClient = apiClient as jest.Mocked<typeof apiClient>;
const mockedUseFabricResolver = useFabricResolver as jest.Mock;

const surface = (surfaceId: string, name: string, tags: string[]) => ({
  surface_id: surfaceId,
  name,
  tags,
  access_point: { protocol: 'a2a' },
});

const task = (taskId: string, configId: string, channelName: string) => ({
  task_id: taskId,
  config_id: configId,
  channel_name: channelName,
  transit_point: null,
  listen_address: '127.0.0.1:5000',
  target_endpoint: 'https://target.example.com',
  started_at: '2026-01-01T00:00:00Z',
  status: 'running',
  total_connections: 0,
  active_connections: 0,
  bytes_sent: 0,
  bytes_received: 0,
  last_activity: null,
  error_count: 0,
});

describe('TasksPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedUseFabricResolver.mockReturnValue({ formatFabric: jest.fn(() => null) });
  });

  it('excludes tasks whose config_id is not a known surface', async () => {
    const stats = {
      tasks: {
        tasks: [
          task('task-alpha', 'surface-alpha', 'Surface Alpha'),
          task('task-beta', 'surface-beta', 'Surface Beta'),
          task('task-unknown', 'unknown-surface', 'Surface Alpha'),
        ],
        metrics: [],
      },
      connection_point_tasks: { tasks: [], summary: undefined },
    };

    mockedApiClient.listSurfaces.mockResolvedValue([
      surface('surface-alpha', 'Surface Alpha', ['alpha']),
      surface('surface-beta', 'Surface Beta', ['beta']),
    ] as any);
    mockedUseApp.mockReturnValue({
      state: {},
      actions: { setWsSubscription: jest.fn() },
      getCurrentStats: jest.fn(() => stats),
    });

    render(
      <MemoryRouter>
        <TasksPage />
      </MemoryRouter>
    );

    expect(await screen.findByText('Surface Alpha')).toBeInTheDocument();
    expect(screen.getByText('2', { selector: '.h5' })).toBeInTheDocument();
  });

  it('counts only tasks in the selected surface tag', async () => {
    const stats = {
      tasks: {
        tasks: [
          task('task-alpha', 'surface-alpha', 'Surface Alpha'),
          task('task-beta', 'surface-beta', 'Surface Beta'),
        ],
        metrics: [],
      },
      connection_point_tasks: { tasks: [], summary: undefined },
    };

    mockedApiClient.listSurfaces.mockResolvedValue([
      surface('surface-alpha', 'Surface Alpha', ['alpha']),
      surface('surface-beta', 'Surface Beta', ['beta']),
    ] as any);
    mockedUseApp.mockReturnValue({
      state: {},
      actions: { setWsSubscription: jest.fn() },
      getCurrentStats: jest.fn(() => stats),
    });

    render(
      <MemoryRouter>
        <TasksPage />
      </MemoryRouter>
    );

    const alphaFilter = await screen.findByTitle("Filter to 'alpha'");
    fireEvent.click(alphaFilter);

    expect(await screen.findByText('1', { selector: '.h5' })).toBeInTheDocument();
  });
});
