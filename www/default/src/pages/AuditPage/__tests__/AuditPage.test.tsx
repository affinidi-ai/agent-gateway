import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import AuditPage from '..';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: {
    get: jest.fn(),
    listIssuers: jest.fn(() => Promise.resolve([])),
  },
}));

jest.mock('../../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

let mockAuditEnabled: boolean | undefined = true;
jest.mock('../../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: { audit_enabled: mockAuditEnabled } } }),
}));

const mockGet = apiClient.get as jest.Mock;

const AUDIT_RESPONSE = {
  events: [
    {
      id: 'entry-1',
      timestamp: '2026-02-01T10:00:00Z',
      event: {
        policy_decision: {
          scope: 'surface',
          flow: 'transit_point',
          policy_id: 'surface.policy',
          policy_name: 'My Surface Policy',
          policy_definition_id: 'def-uuid-1',
          decision: 'deny',
          deny_reason: 'blocked by policy',
          surface_id: 'surface-1',
          caller_did: 'did:web:example.com:agent',
          http_method: 'POST',
          http_path: '/v1/message',
        },
      },
      surface_id: 'surface-1',
      channel_name: 'Weather Surface',
      caller: { auth_method: 'jwt_bearer', did: 'did:web:example.com:agent' },
      trace_id: 'trace-1',
      via_fabric: false,
    },
    {
      id: 'entry-2',
      timestamp: '2026-02-01T10:05:00Z',
      event: 'token_injected',
      provider_id: 'prov-1',
      provider_name: 'GitHub',
      via_fabric: true,
    },
  ],
  total: 2,
  page: 1,
  limit: 50,
  category_counts: { policy_decision: 1, token_injected: 1 },
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AuditPage />
    </MemoryRouter>
  );
}

/** Locate a filter facet container by its "Label:" heading text. */
function facet(label: string): HTMLElement {
  return screen.getByText(label).parentElement as HTMLElement;
}

describe('AuditPage', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockResolvedValue({ data: AUDIT_RESPONSE });
  });

  it('renders the page shell, filter tabs and refresh control with stable test ids', async () => {
    renderPage();

    expect(await screen.findByTestId('page-audit')).toBeInTheDocument();
    expect(screen.getByTestId('audit-search')).toBeInTheDocument();
    expect(screen.getByTestId('audit-refresh')).toBeInTheDocument();

    // Category facet: the "All" chip is always inline; a category with a
    // non-zero count (from category_counts) renders inline once data loads.
    const categoryFacet = facet('Category:');
    expect(within(categoryFacet).getByTestId('filter-chip-all')).toBeInTheDocument();
    expect(
      await within(categoryFacet).findByTestId('filter-chip-policy_decision')
    ).toBeInTheDocument();

    // Decision facet: All / Allow / Deny inline chips.
    const decisionFacet = facet('Decision:');
    expect(within(decisionFacet).getByTestId('filter-chip-all')).toBeInTheDocument();
    expect(within(decisionFacet).getByTestId('filter-chip-allow')).toBeInTheDocument();
    expect(within(decisionFacet).getByTestId('filter-chip-deny')).toBeInTheDocument();

    expect(await screen.findByTestId('audit-list')).toBeInTheDocument();
  });

  it('keeps the evidence panel open by default and swaps it on selection', async () => {
    renderPage();

    // Panel is open on load, showing the newest (first) event.
    const item0 = await screen.findByTestId('audit-item-0');
    expect(item0.tagName).toBe('BUTTON');
    expect(item0).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('audit-detail-panel')).toHaveAttribute('data-open', 'true');
    const evidence = await screen.findByTestId('audit-evidence');
    // The evidence pane leads with the request journey timeline.
    expect(within(evidence).getByTestId('audit-journey')).toBeInTheDocument();
    // The quick filters live in the non-scrolling panel header, not the evidence body.
    const panel = screen.getByTestId('audit-detail-panel');
    expect(within(panel).getByTestId('audit-quick-filters')).toBeInTheDocument();
    expect(within(evidence).queryByTestId('audit-quick-filters')).not.toBeInTheDocument();

    // Selecting another event swaps the panel content and moves the selection.
    fireEvent.click(screen.getByTestId('audit-item-1'));
    expect(screen.getByTestId('audit-item-1')).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('audit-item-0')).toHaveAttribute('aria-current', 'false');
    expect(screen.getByTestId('audit-detail-panel')).toHaveAttribute('data-open', 'true');
  });

  it('sends the selected categories as an OR set and the About banner is collapsed by default', async () => {
    renderPage();

    // About banner collapsed initially, expands on toggle.
    const about = await screen.findByTestId('audit-about-toggle');
    expect(about).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(about);
    expect(about).toHaveAttribute('aria-expanded', 'true');

    // Selecting two categories issues an OR-set (comma-separated) query.
    const categoryFacet = facet('Category:');

    // policy_decision is an inline chip once its count loads.
    fireEvent.click(await within(categoryFacet).findByTestId('filter-chip-policy_decision'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('category=policy_decision'))
    );

    // trust_check has no count, so it lives in the Category overflow menu.
    fireEvent.click(within(categoryFacet).getByTestId('filter-overflow-trigger-category'));
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-trust_check'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('category=policy_decision%2Ctrust_check')
      )
    );
  });

  it('filters rows server-side by the policy-decision flow marker', async () => {
    // The server applies the flow filter, so the mock echoes it: flow=access_point
    // returns no matching policy decisions, otherwise the transit_point row.
    mockGet.mockImplementation((url: string) => {
      if (url.includes('flow=access_point')) {
        return Promise.resolve({
          data: { events: [], total: 0, page: 1, limit: 50, category_counts: {} },
        });
      }
      return Promise.resolve({ data: AUDIT_RESPONSE });
    });

    renderPage();

    // The transit_point policy decision shows initially, its flow named in the summary.
    const initialRow = await screen.findByTestId('audit-item-0');
    expect(within(initialRow).getByText(/Transit Point/)).toBeInTheDocument();

    // Flow options live in the Flow overflow menu.
    const flowFacet = facet('Flow:');
    fireEvent.click(within(flowFacet).getByTestId('filter-overflow-trigger-flow'));
    expect(screen.getByTestId('filter-overflow-checkbox-transit_point')).toBeInTheDocument();

    // Filtering by flow=access_point issues a server query and clears the rows.
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-access_point'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('flow=access_point'))
    );
    await waitFor(() => expect(screen.queryByTestId('audit-item-0')).not.toBeInTheDocument());

    // Filtering by flow=transit_point brings the row back.
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-transit_point'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('flow=transit_point'))
    );
    const row = await screen.findByTestId('audit-item-0');
    expect(within(row).getByText(/Transit Point/)).toBeInTheDocument();

    // Type (scope) options live in the Type overflow menu.
    const typeFacet = facet('Type:');
    fireEvent.click(within(typeFacet).getByTestId('filter-overflow-trigger-type'));
    expect(screen.getByTestId('filter-overflow-checkbox-gateway')).toBeInTheDocument();
  });
});

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderWithRoutes() {
  return render(
    <MemoryRouter initialEntries={['/audit']}>
      <Routes>
        <Route path="/audit" element={<AuditPage />} />
        <Route path="*" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>
  );
}

function withIntegrations(
  integrations: Array<{ category?: string; status: string; tenant_id?: string }>,
  categories = ['general', 'audit']
) {
  mockGet.mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === '/integrations'
          ? integrations
          : url === '/integrations/config'
            ? { categories: categories.map(enum_value => ({ enum_value })) }
            : AUDIT_RESPONSE,
    })
  );
}

describe('AuditPage forwarding', () => {
  beforeEach(() => {
    mockGet.mockReset();
    mockAuditEnabled = true;
  });

  it('leaves tenant-owned integrations out of the count, as the gateway never forwards to them', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([
      { category: 'audit', status: 'active' },
      { category: 'audit', status: 'active', tenant_id: 'tenant-a' },
    ]);
    renderWithRoutes();

    expect(await screen.findByTestId('audit-forward-button')).toHaveTextContent(
      /^Forwarding to 1 integration$/
    );
  });

  it('says forwarding is idle while VP Auditing is off', async () => {
    mockPermissions = { 'integrations.view': true };
    mockAuditEnabled = false;
    withIntegrations([{ category: 'audit', status: 'active' }]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent('Forwarding to 1 integration (VP Auditing off)');
    expect(button).toHaveAttribute('title', expect.stringContaining('Settings › Security'));
  });

  it('offers no forwarding when the gateway has no Governance Audit category', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([], ['general', 'gateway']);
    renderWithRoutes();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations/config'));
    await screen.findByTestId('audit-list');
    expect(screen.queryByTestId('audit-forward-button')).not.toBeInTheDocument();
  });

  it('starts a Governance Audit stream when no integration receives the records', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([{ category: 'gateway', status: 'active' }]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent('Forward records');
    fireEvent.click(button);
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/integrations/integrations/wizard?category=audit&type=stream'
    );
  });

  it('counts only active Governance Audit integrations and opens the list', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([
      { category: 'audit', status: 'active' },
      { category: 'audit', status: 'active' },
      { category: 'audit', status: 'disabled' },
      { category: 'gateway', status: 'active' },
    ]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent('Forwarding to 2 integrations');
    fireEvent.click(button);
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/integrations$/);
  });

  it('shows existing forwarding to a caller who cannot add integrations', async () => {
    mockPermissions = { 'integrations.view': true };
    withIntegrations([{ category: 'audit', status: 'active' }]);
    renderWithRoutes();

    expect(await screen.findByTestId('audit-forward-button')).toHaveTextContent(
      /^Forwarding to 1 integration$/
    );
  });

  it('offers nothing to a caller who can view but not add integrations when none forward', async () => {
    mockPermissions = { 'integrations.view': true };
    withIntegrations([]);
    renderWithRoutes();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations'));
    await screen.findByTestId('audit-list');
    expect(screen.queryByTestId('audit-forward-button')).not.toBeInTheDocument();
  });

  it('does not look up integrations without integrations.view', async () => {
    mockPermissions = {};
    withIntegrations([{ category: 'audit', status: 'active' }]);
    renderWithRoutes();

    await screen.findByTestId('audit-list');
    expect(mockGet).not.toHaveBeenCalledWith('/integrations');
    expect(screen.queryByTestId('audit-forward-button')).not.toBeInTheDocument();
  });
});
