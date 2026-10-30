import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import AddSurfacePage from '../AddSurfacePage';
import { apiClient } from '../../api';
import type { AgentSurface } from '../../api';
import { fetchRoutingConfig } from '../../components/surface-builder/elements/access-point/defaults';
import { showToast } from '../../utils/toaster';

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
      <output data-testid="selected-node">{props.builder.state.selectedNodeId ?? ''}</output>
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

  it('blocks a surface with no Caller Context and Public access off, with Show me', async () => {
    renderPage();
    await routeSeeded();

    create();

    expect(createSurface).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledTimes(1);
    const [type, message, options] = toast.mock.calls[0];
    expect(type).toBe('error');
    expect(message).toBe(
      'This Access Point is closed to all callers. Add a Caller Context, or turn on Public access.'
    );
    expect(options.action.label).toBe('Show me');

    act(() => options.action.onClick());
    expect(screen.getByTestId('selected-node')).toHaveTextContent('access-point');
  });

  it('creates a public surface and warns that it is public', async () => {
    renderPage();
    await routeSeeded();
    fireEvent.click(screen.getByText('Turn on Public access'));

    create();

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        'warning',
        'Warning: This Access Point is public. Anyone who can reach it can call your agent without credentials.',
        expect.anything()
      )
    );
    expect(createSurface).toHaveBeenCalledTimes(1);
    expect(createSurface.mock.calls[0][0].access_point.public).toBe(true);
  });
});
