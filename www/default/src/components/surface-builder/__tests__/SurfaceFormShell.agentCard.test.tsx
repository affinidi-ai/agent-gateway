import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SurfaceFormShell, { visibleSidebarViews, type SurfaceFormView } from '../SurfaceFormShell';
import type { Protocol } from '../elements/types';
import { apiClient } from '../../../api';
import { failedBody, previewBody } from '../../../utils/agentCardTestFixtures';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn(), get: jest.fn().mockResolvedValue({ data: [] }) },
}));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../SurfaceCanvas', () => ({ getIncompleteReason: () => null }));
jest.mock('../SurfaceBuilder', () => {
  const AgentCardFetchLine = jest.requireActual('../agent-card/AgentCardFetchLine').default;
  return () => (
    <div data-testid="canvas-stub">
      <AgentCardFetchLine />
    </div>
  );
});

const mockFetch = apiClient.fetch as jest.Mock;
const reply = (status: number, body: unknown = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

const noop = () => undefined;
const builder = {
  state: { nodes: [], selectedNodeId: null },
  handleNodeClick: noop,
  handleNodeUpdate: noop,
} as never;

const META = {
  name: 'a2a_surface_1',
  description: '',
  tagsCsv: '',
  status: 'active',
  protocol: 'a2a' as Protocol,
  publishToDid: false,
  terminateTraceId: false,
  issuerId: '',
  didwebvh: {
    enabled: false,
    auto_create: true,
    identity_id: '',
    did_path: '',
    injection_mode: 'header' as const,
  },
};

const setters = {
  setName: noop,
  setDescription: noop,
  setTagsCsv: noop,
  setStatus: noop,
  setProtocol: noop,
  setPublishToDid: noop,
  setTerminateTraceId: noop,
  setIssuerId: noop,
  setDidwebvh: noop,
};

interface HarnessProps {
  mode?: 'create' | 'edit';
  protocol?: Protocol;
  surfaceId?: string;
  initialTab?: SurfaceFormView;
  isDirty?: boolean;
  canEdit?: boolean;
  saveError?: string | null;
}

const Harness: React.FC<HarnessProps> = ({
  mode = 'edit',
  protocol = 'a2a',
  surfaceId = 's-123',
  initialTab = 'surface',
  isDirty = false,
  canEdit = true,
  saveError = null,
}) => {
  const [activeTab, setActiveTab] = useState<SurfaceFormView>(initialTab);
  return (
    <>
      <output data-testid="active-tab">{activeTab}</output>
      <SurfaceFormShell
        mode={mode}
        canEdit={canEdit}
        builder={builder}
        meta={{ ...META, protocol } as never}
        setMeta={setters as never}
        jsonOverride={null}
        setJsonOverride={noop}
        jsonError={null}
        setJsonError={noop}
        configEditorValue="{}"
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        editorTabNodeId={null}
        onOpenFullscreenEditor={noop}
        onCloseFullscreenEditor={noop}
        surfaceId={mode === 'edit' ? surfaceId : undefined}
        surfacePolicyLoadState={{ status: 'loaded', ids: new Set<string>() } as never}
        saveError={saveError}
        otherVariantSnapshots={[]}
        isDirty={isDirty}
        agentCardRefreshKey={0}
      />
    </>
  );
};

const viewKeys = () =>
  screen.getAllByTestId(/^surface-view-/).map(el => el.getAttribute('data-testid'));

const fetchedUrls = () => mockFetch.mock.calls.map(call => call[0]);

beforeEach(() => {
  jest.clearAllMocks();
  mockFetch.mockResolvedValue(reply(200, previewBody()));
});

describe('sidebar views', () => {
  it('lists Agent Cards after Elements and before Monitoring for A2A and AP2', () => {
    expect(visibleSidebarViews('edit', 'a2a').map(v => v.key)).toEqual([
      'surface',
      'templates',
      'elements',
      'agent-card',
      'monitoring',
      'config',
    ]);
    expect(visibleSidebarViews('edit', 'ap2').map(v => v.key)).toEqual([
      'surface',
      'templates',
      'elements',
      'agent-card',
      'monitoring',
      'config',
    ]);
    expect(visibleSidebarViews('create', 'a2a').map(v => v.key)).toEqual([
      'surface',
      'templates',
      'elements',
      'agent-card',
      'config',
    ]);
    expect(visibleSidebarViews('edit', 'a2a').find(v => v.key === 'agent-card')).toMatchObject({
      label: 'Agent Cards',
      icon: 'fa-id-card',
    });
  });

  it('offers no Agent Cards view for MCP or DIDComm', () => {
    for (const protocol of ['mcp', 'didcomm'] as const) {
      expect(visibleSidebarViews('edit', protocol).map(v => v.key)).toEqual([
        'surface',
        'templates',
        'elements',
        'monitoring',
        'config',
      ]);
    }
  });
});

describe('SurfaceFormShell Agent Cards view', () => {
  it('renders the sidebar button after Elements for a saved A2A surface', () => {
    render(<Harness />);
    expect(viewKeys()).toEqual([
      'surface-view-surface',
      'surface-view-templates',
      'surface-view-elements',
      'surface-view-agent-card',
      'surface-view-monitoring',
      'surface-view-config',
    ]);
    const button = screen.getByRole('button', { name: 'Agent Cards' });
    expect(button).toHaveAttribute('data-testid', 'surface-view-agent-card');
    expect(button).not.toHaveAttribute('aria-current');
    expect(screen.getByTestId('surface-view-surface')).toHaveAttribute('aria-current', 'page');
  });

  it('shows the button for AP2 and hides it for MCP and DIDComm', () => {
    const { unmount } = render(<Harness protocol="ap2" />);
    expect(screen.getByTestId('surface-view-agent-card')).toBeInTheDocument();
    unmount();
    for (const protocol of ['mcp', 'didcomm'] as const) {
      const view = render(<Harness protocol={protocol} />);
      expect(screen.queryByTestId('surface-view-agent-card')).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Agent Cards' })).not.toBeInTheDocument();
      view.unmount();
    }
  });

  it('opens the view and reads the cards of the saved surface', async () => {
    render(<Harness />);
    expect(screen.queryByTestId('agent-card-tab')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('surface-view-agent-card'));
    expect(screen.getByTestId('active-tab')).toHaveTextContent('agent-card');
    expect(screen.getByTestId('surface-view-agent-card')).toHaveAttribute('aria-current', 'page');
    expect(await screen.findByTestId('agent-card-summary')).toBeInTheDocument();
    expect(fetchedUrls()).toContain('/api/v1/surfaces/s-123/agent-card');
    expect(screen.getByTestId('canvas-stub')).not.toBeVisible();
  });

  it('links back to the Surface view', async () => {
    render(<Harness initialTab="agent-card" />);
    fireEvent.click(await screen.findByTestId('agent-card-open-surface-button'));
    expect(screen.getByTestId('active-tab')).toHaveTextContent('surface');
    expect(screen.queryByTestId('agent-card-tab')).not.toBeInTheDocument();
    expect(screen.getByTestId('canvas-stub')).toBeVisible();
  });

  it('moves focus to the Surface view button after the link from the Agent Cards view', async () => {
    render(<Harness initialTab="agent-card" />);
    const link = await screen.findByTestId('agent-card-open-surface-button');
    link.focus();
    fireEvent.click(link);
    expect(screen.getByTestId('surface-view-surface')).toHaveFocus();
  });

  it('explains in create mode that the surface must be saved first', () => {
    render(<Harness mode="create" initialTab="agent-card" />);
    expect(screen.getByTestId('agent-card-unsaved')).toBeInTheDocument();
    expect(fetchedUrls()).not.toContain('/api/v1/surfaces/s-123/agent-card');
  });

  it('warns that the cards show the saved surface when there are unsaved changes', async () => {
    render(<Harness initialTab="agent-card" isDirty />);
    expect(await screen.findByTestId('agent-card-unsaved-changes')).toBeInTheDocument();
  });

  it('says nothing about unsaved changes when the form matches the saved surface', async () => {
    render(<Harness initialTab="agent-card" />);
    await screen.findByTestId('agent-card-summary');
    expect(screen.queryByTestId('agent-card-unsaved-changes')).not.toBeInTheDocument();
  });

  it('disables Refresh when the user cannot edit surfaces', async () => {
    render(<Harness initialTab="agent-card" canEdit={false} />);
    await waitFor(() => expect(screen.getByTestId('agent-card-refresh-button')).toBeDisabled());
  });

  it('returns to the canvas when the protocol no longer has Agent Cards', async () => {
    const view = render(<Harness initialTab="agent-card" />);
    await screen.findByTestId('agent-card-tab');
    view.rerender(<Harness initialTab="agent-card" protocol="mcp" />);
    await waitFor(() => expect(screen.getByTestId('active-tab')).toHaveTextContent('surface'));
    expect(screen.queryByTestId('agent-card-tab')).not.toBeInTheDocument();
  });

  it('stays on another view when the protocol changes', async () => {
    const view = render(<Harness initialTab="config" />);
    view.rerender(<Harness initialTab="config" protocol="mcp" />);
    await waitFor(() => expect(screen.getByTestId('active-tab')).toHaveTextContent('config'));
  });

  it('lets the Managed Agent card line open the view', async () => {
    render(<Harness />);
    fireEvent.click(await screen.findByTestId('managed-agent-card-fetch-link'));
    expect(screen.getByTestId('active-tab')).toHaveTextContent('agent-card');
    expect(await screen.findByTestId('agent-card-summary')).toBeInTheDocument();
  });

  it('moves focus to the Agent Cards view button after the Managed Agent card line link', async () => {
    render(<Harness />);
    const link = await screen.findByTestId('managed-agent-card-fetch-link');
    link.focus();
    fireEvent.click(link);
    expect(screen.getByTestId('surface-view-agent-card')).toHaveFocus();
  });

  it('does not move focus when the user picks a view from the sidebar', async () => {
    render(<Harness />);
    const elements = screen.getByTestId('surface-view-elements');
    const agentCards = screen.getByTestId('surface-view-agent-card');
    elements.focus();
    fireEvent.click(agentCards);
    expect(elements).toHaveFocus();
  });

  it('updates the Managed Agent card line after a Refresh in the Agent Cards view', async () => {
    mockFetch.mockResolvedValue(reply(200, failedBody('timeout', null)));
    render(<Harness />);
    await waitFor(() =>
      expect(screen.getByTestId('managed-agent-card-fetch-status')).toHaveTextContent(
        'Card fetch: failing (Timed out)'
      )
    );
    fireEvent.click(screen.getByTestId('managed-agent-card-fetch-link'));
    await screen.findByTestId('agent-card-failed');

    mockFetch.mockResolvedValue(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() => expect(screen.queryByTestId('agent-card-failed')).not.toBeInTheDocument());
    fireEvent.click(screen.getByTestId('agent-card-open-surface-button'));
    await waitFor(() =>
      expect(screen.getByTestId('managed-agent-card-fetch-status')).toHaveTextContent(
        'Card fetch: OK'
      )
    );
    expect(fetchedUrls()).toContain('/api/v1/surfaces/s-123/agent-card/refresh');
  });

  it('offers no card line or link where the view is not offered', async () => {
    const { unmount } = render(<Harness protocol="mcp" />);
    expect(screen.queryByTestId('managed-agent-card-fetch')).not.toBeInTheDocument();
    unmount();
    render(<Harness mode="create" />);
    expect(screen.queryByTestId('managed-agent-card-fetch')).not.toBeInTheDocument();
    expect(fetchedUrls()).not.toContain('/api/v1/surfaces/s-123/agent-card');
  });
});
