import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import AddSurfacePage from '../AddSurfacePage';
import { apiClient } from '../../api';
import type { AgentSurface } from '../../api';
import { fetchRoutingConfig } from '../../components/surface-builder/elements/access-point/defaults';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../../components/surface-builder/SurfaceCanvas', () => ({
  getIncompleteReason: () => null,
}));
jest.mock('../../components/surface-builder/elements/access-point/defaults', () => ({
  ...jest.requireActual('../../components/surface-builder/elements/access-point/defaults'),
  fetchRoutingConfig: jest.fn(),
}));
jest.mock('../../components/surface-builder/hooks/useSurfacePolicyDefinitions', () => ({
  useSurfacePolicyDefinitions: () => ({ status: 'loaded', ids: new Set<string>() }),
}));
jest.mock('../../components/surface-builder/templates/useSurfaceTemplates', () => ({
  useSurfaceTemplates: () => ({ templates: [], loading: false, error: null }),
}));
let mockCompleteCanvas = false;
jest.mock('../../components/surface-builder/hooks/useSurfaceBuilder', () => {
  const actual = jest.requireActual('../../components/surface-builder/hooks/useSurfaceBuilder');
  return {
    ...actual,
    useSurfaceBuilder: (...args: unknown[]) => {
      const builder = actual.useSurfaceBuilder(...args);
      if (!mockCompleteCanvas) return builder;
      return {
        ...builder,
        hasIncompleteNodes: false,
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
      <output data-testid="name">{props.meta.name}</output>
      <input
        aria-label="Name"
        value={props.meta.name}
        onChange={e => props.setMeta.setName(e.target.value)}
      />
      <input
        aria-label="Description"
        value={props.meta.description}
        onChange={e => props.setMeta.setDescription(e.target.value)}
      />
      <button onClick={() => props.setMeta.setProtocol('mcp')}>Switch to MCP</button>
      <button onClick={() => props.onApplyJsonPayload(JSON.parse(props.configEditorValue))}>
        Apply config
      </button>
      <button
        onClick={() => {
          const ap = props.builder.state.nodes.find((n: any) => n.id === 'access-point');
          props.builder.handleNodeUpdate('access-point', { ...ap.config, public: true });
        }}
      >
        Turn on Public access
      </button>
      <button
        onClick={() => {
          const target = props.builder.state.nodes.find((n: any) => n.id === 'target');
          props.builder.handleNodeUpdate('target', {
            ...target.config,
            endpoint: 'https://agent.example',
          });
        }}
      >
        Set target
      </button>
      <output data-testid="access-point-notice">{props.accessPointNotice ?? ''}</output>
      {props.manageActions}
    </div>
  );
}

jest.mock('../../utils/toaster', () => ({
  ...jest.requireActual('../../utils/toaster'),
  showToast: jest.fn(),
}));

if (typeof globalThis.crypto?.randomUUID !== 'function') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { randomUUID: () => '00000000-0000-4000-8000-000000000000' },
    configurable: true,
  });
}

const routingConfig = fetchRoutingConfig as jest.Mock;

const existing = [
  { name: 'a2a_surface_1', access_point: { protocol: 'a2a' } },
] as unknown as AgentSurface[];

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  const d = {} as Deferred<T>;
  d.promise = new Promise<T>((resolve, reject) => {
    d.resolve = resolve;
    d.reject = reject;
  });
  return d;
}

const isDirty = () => {
  const ev = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(ev);
  return ev.defaultPrevented;
};

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/surfaces/new?protocol=a2a']}>
      <AddSurfacePage />
    </MemoryRouter>
  );

const routeSeeded = () =>
  act(async () => {
    await routingConfig.mock.results[0].value;
  });

const editDescription = () =>
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'edited' } });

describe('AddSurfacePage default name and unsaved changes', () => {
  let list: Deferred<AgentSurface[]>;

  beforeEach(() => {
    jest.restoreAllMocks();
    routingConfig.mockReset();
    routingConfig.mockResolvedValue({
      available_listen_addresses: ['https://gw.example'],
      channel_path_prefix: [{ id: 'agents', name: 'Agents', prefix: '/agents' }],
    });
    list = deferred<AgentSurface[]>();
    jest.spyOn(apiClient, 'listSurfaces').mockReturnValue(list.promise);
  });

  it('numbers past existing surfaces without marking the page dirty', async () => {
    renderPage();
    await routeSeeded();
    expect(screen.getByTestId('name')).toHaveTextContent(/^a2a_surface_1$/);

    await act(async () => list.resolve(existing));

    expect(screen.getByTestId('name')).toHaveTextContent(/^a2a_surface_2$/);
    expect(isDirty()).toBe(false);
    editDescription();
    expect(isDirty()).toBe(true);
  });

  it('falls back to the first name when the list fails, without marking the page dirty', async () => {
    renderPage();
    await routeSeeded();

    await act(async () => list.reject(new Error('offline')));

    expect(screen.getByTestId('name')).toHaveTextContent(/^a2a_surface_1$/);
    expect(isDirty()).toBe(false);
    editDescription();
    expect(isDirty()).toBe(true);
  });

  it('follows a protocol switch', async () => {
    renderPage();
    await routeSeeded();
    await act(async () => list.resolve(existing));

    fireEvent.click(screen.getByText('Switch to MCP'));

    expect(screen.getByTestId('name')).toHaveTextContent(/^mcp_surface_1$/);
  });

  it('keeps a typed name across a protocol switch', async () => {
    renderPage();
    await routeSeeded();
    await act(async () => list.resolve(existing));

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'payments' } });
    fireEvent.click(screen.getByText('Switch to MCP'));

    expect(screen.getByTestId('name')).toHaveTextContent(/^payments$/);
  });

  it('treats a typed name equal to the generated one as the default', async () => {
    renderPage();
    await routeSeeded();
    await act(async () => list.resolve(existing));

    const nameInput = screen.getByLabelText('Name');
    fireEvent.change(nameInput, { target: { value: 'a2a_surface_2x' } });
    expect(isDirty()).toBe(true);
    fireEvent.change(nameInput, { target: { value: 'a2a_surface_2' } });

    expect(isDirty()).toBe(false);
    fireEvent.click(screen.getByText('Switch to MCP'));
    expect(screen.getByTestId('name')).toHaveTextContent(/^mcp_surface_1$/);
  });

  it('marks the page dirty when an edit lands before the list loads', async () => {
    renderPage();
    await routeSeeded();

    editDescription();
    await act(async () => list.resolve(existing));

    expect(screen.getByTestId('name')).toHaveTextContent(/^a2a_surface_2$/);
    expect(isDirty()).toBe(true);
  });

  it('keeps the generated name following the protocol after an unchanged Config apply', async () => {
    renderPage();
    await routeSeeded();
    await act(async () => list.resolve(existing));

    fireEvent.click(screen.getByText('Apply config'));
    expect(screen.getByTestId('name')).toHaveTextContent(/^a2a_surface_2$/);
    fireEvent.click(screen.getByText('Switch to MCP'));

    expect(screen.getByTestId('name')).toHaveTextContent(/^mcp_surface_1$/);
  });

  it('keeps a typed name after an unchanged Config apply and a protocol switch', async () => {
    renderPage();
    await routeSeeded();
    await act(async () => list.resolve(existing));

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'payments' } });
    fireEvent.click(screen.getByText('Apply config'));
    fireEvent.click(screen.getByText('Switch to MCP'));

    expect(screen.getByTestId('name')).toHaveTextContent(/^payments$/);
  });
});

describe('AddSurfacePage caller access on create', () => {
  const toast = showToast as jest.Mock;
  let createSurface: jest.SpyInstance;

  beforeEach(() => {
    jest.restoreAllMocks();
    toast.mockReset();
    routingConfig.mockReset();
    routingConfig.mockResolvedValue({
      available_listen_addresses: ['https://gw.example'],
      channel_path_prefix: [{ id: 'agents', name: 'Agents', prefix: '/agents' }],
    });
    jest.spyOn(apiClient, 'listSurfaces').mockResolvedValue([]);
    createSurface = jest
      .spyOn(apiClient, 'createSurface')
      .mockResolvedValue({} as unknown as AgentSurface);
  });

  const create = () => {
    fireEvent.click(screen.getByText('Set target'));
    const button = screen.getByTestId('add-surface-create-button');
    expect(button).toBeEnabled();
    fireEvent.click(button);
  };

  it("creates a surface with no Caller Context and shows the response's not-ready warning", async () => {
    const notReady =
      'This Access Point is not ready for external access. Add source authentication (a caller_authentication method), or set access_point.public to true to allow callers without credentials.';
    createSurface.mockResolvedValue({ warnings: [notReady] } as unknown as AgentSurface);
    renderPage();
    await routeSeeded();

    create();

    await waitFor(() => expect(createSurface).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        'warning',
        expect.stringContaining(`created, with warnings:\n${notReady}`),
        expect.anything()
      )
    );
    expect(toast.mock.calls.filter(c => c[0] === 'error')).toEqual([]);
    expect(toast.mock.calls.filter(c => c[0] === 'warning')).toHaveLength(1);
  });

  it('shows the not-ready notice from the draft until Public access is on', async () => {
    renderPage();
    await routeSeeded();

    expect(screen.getByTestId('access-point-notice')).toHaveTextContent(/^not_ready$/);
    fireEvent.click(screen.getByText('Turn on Public access'));
    expect(screen.getByTestId('access-point-notice')).toHaveTextContent(/^$/);
  });

  it("creates a public surface and shows the response's public warning once", async () => {
    const publicMessage =
      'This Access Point is public. Anyone who can reach it can call your agent without credentials.';
    createSurface.mockResolvedValue({ warnings: [publicMessage] } as unknown as AgentSurface);
    renderPage();
    await routeSeeded();
    fireEvent.click(screen.getByText('Turn on Public access'));

    create();

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        'warning',
        expect.stringContaining(`created, with warnings:\n${publicMessage}`),
        expect.anything()
      )
    );
    expect(toast.mock.calls.filter(c => c[0] === 'warning')).toHaveLength(1);
    expect(createSurface).toHaveBeenCalledTimes(1);
    expect(createSurface.mock.calls[0][0].access_point.public).toBe(true);
  });
});

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location">
      {location.pathname} {JSON.stringify(location.state)}
    </output>
  );
}

describe('AddSurfacePage create warnings', () => {
  beforeAll(() => {
    mockCompleteCanvas = true;
  });
  afterAll(() => {
    mockCompleteCanvas = false;
  });

  const warning =
    "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: 0.0.0.0:8080";

  beforeEach(() => {
    jest.restoreAllMocks();
    (showToast as jest.Mock).mockReset();
    routingConfig.mockReset();
    routingConfig.mockResolvedValue({
      available_listen_addresses: ['https://gw.example'],
      channel_path_prefix: [{ id: 'agents', name: 'Agents', prefix: '/agents' }],
    });
    jest.spyOn(apiClient, 'listSurfaces').mockResolvedValue(existing);
  });

  const renderAt = () =>
    render(
      <MemoryRouter initialEntries={['/surfaces/new?protocol=a2a']}>
        <Routes>
          <Route path="/surfaces/new" element={<AddSurfacePage />} />
          <Route path="*" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    );

  const create = async (warnings: string[]) => {
    jest.spyOn(apiClient, 'createSurface').mockImplementation(async (_payload, options) => {
      options?.onWarnings?.(warnings);
      return { surface_id: 'new-id' } as AgentSurface;
    });
    renderAt();
    await routeSeeded();
    fireEvent.click(screen.getByTitle('Create surface'));
    await waitFor(() => expect(showToast).toHaveBeenCalled());
  };

  it("opens the new surface's page with the gateway warnings, in one toast", async () => {
    await create([warning]);

    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(
      'warning',
      expect.stringContaining(`created, with warnings:\n${warning}`),
      expect.objectContaining({ autoRemove: true })
    );
    expect(screen.getByTestId('location')).toHaveTextContent(
      `/surfaces/new-id ${JSON.stringify({ saveWarnings: [warning] })}`
    );
  });

  it('returns to the surface list when the gateway answers with none', async () => {
    await create([]);

    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('Transit Point'),
      expect.anything()
    );
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/surfaces null$/);
  });
});
