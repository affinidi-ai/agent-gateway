import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import AddSurfacePage from '../AddSurfacePage';
import { apiClient } from '../../api';
import type { AgentSurface } from '../../api';
import { fetchRoutingConfig } from '../../components/surface-builder/elements/access-point/defaults';

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
    </div>
  );
}

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
