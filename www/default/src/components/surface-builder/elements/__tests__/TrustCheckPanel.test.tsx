import React from 'react';
import { act, render, screen, fireEvent } from '@testing-library/react';
import TrustCheckPanel from '../trust-check/TrustCheckPanel';
import TrustCheckFullscreenPanel from '../trust-check/TrustCheckFullscreenPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';

jest.mock('../../../../api', () => ({
  apiClient: {
    listTrustRegistries: () => Promise.resolve([{ id: 'tr-1', name: 'Partner Registry' }]),
  },
}));
jest.mock('../../../../utils/issuersCache', () => ({
  getIssuers: () =>
    Promise.resolve([{ id: 'd-1', name: 'Acme Issuer', did: 'did:web:issuer.example' }]),
}));
jest.mock('../../../../utils/authoritiesCache', () => ({
  getAuthorities: () =>
    Promise.resolve([
      { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' },
      { id: 'a-a', name: 'authority-A', did: 'did:web:authority-a' },
      { id: 'a-b', name: 'authority-B', did: 'did:web:authority-b' },
      { id: 'a-c', name: 'authority-C', did: 'did:web:authority-c' },
    ]),
}));

const AP_SLOT = 'request:trust-check-access_point_trust_check_list';
const TP_SLOT = 'request:trust-check-transit_points_trust_check_list';
const MA_SLOT = 'request:trust-check-target_trust_check_list';

function baseProps(slotId: string, config: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'tc-1',
      type: 'trust-check',
      label: '',
      configured: true,
      config,
      parentId: slotId.includes('access_point')
        ? 'access-point'
        : slotId.includes('transit_points')
          ? 'tp-1'
          : 'target',
      slotId,
    } as any,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    openFullscreenEditor: jest.fn(),
  };
}

const withTarget = (endpoint: string) => [
  { id: 'target', type: 'target', label: '', configured: true, config: { endpoint } },
];

describe('TrustCheckPanel — leg scope', () => {
  it('states that a Transit Point Trust Check applies to that Transit Point only', () => {
    render(<TrustCheckPanel {...(baseProps(TP_SLOT) as any)} />);

    expect(screen.getByTestId('trust-check-panel-transit-point-scope')).toHaveTextContent(
      'Applies to this Transit Point only.'
    );
    expect(screen.getByTestId('trust-check-panel-results-ref')).toHaveTextContent(
      'input.trust_check_results.target[]'
    );
  });

  it('shows no Transit Point scope line on the caller leg', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    expect(screen.queryByTestId('trust-check-panel-transit-point-scope')).toBeNull();
  });

  it('warns that a Managed Agent target-leg Trust Check blocks Save on a URL target', () => {
    render(
      <TrustCheckPanel
        {...(baseProps(MA_SLOT) as any)}
        allNodes={withTarget('https://agent.example.com')}
      />
    );

    expect(screen.getByTestId('trust-check-panel-managed-agent-target-warning')).toHaveTextContent(
      'This Trust Check blocks Save on a URL target'
    );
    expect(screen.queryByTestId('trust-check-panel-transit-point-scope')).toBeNull();
  });

  it.each(['a2a-proxy://proxy-1', 'fabric://gw-1/surface'])(
    'does not warn on the Managed Agent target leg for %s',
    endpoint => {
      render(<TrustCheckPanel {...(baseProps(MA_SLOT) as any)} allNodes={withTarget(endpoint)} />);

      expect(screen.queryByTestId('trust-check-panel-managed-agent-target-warning')).toBeNull();
    }
  );
});

describe('TrustCheckPanel — intro and banner', () => {
  it('opens with what the caller leg checks and where the results land', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    expect(screen.getByTestId('trust-check-panel-results-ref')).toHaveTextContent(
      'Checks the caller against a trust registry before the request reaches the agent. Results land on OPA at input.trust_check_results.caller[]; OPA decides allow or deny.'
    );
  });

  it('opens with what the target leg checks on a Transit Point', () => {
    render(<TrustCheckPanel {...(baseProps(TP_SLOT) as any)} />);

    expect(screen.getByTestId('trust-check-panel-results-ref')).toHaveTextContent(
      /^Checks the target agent .* leaves the gateway\. .* Applies to this Transit Point only\.$/
    );
  });

  it.each([
    [AP_SLOT, /CALLER identity/],
    [TP_SLOT, /TARGET identity/],
  ])('shows one collapsed "How does OPA use the result?" banner (%s)', (slot, summary) => {
    render(<TrustCheckPanel {...(baseProps(slot) as any)} />);

    const toggle = screen.getByTestId('trust-check-panel-context-toggle');
    expect(toggle).toHaveTextContent('How does OPA use the result?');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('trust-check-panel-context-body')).toBeNull();

    fireEvent.click(toggle);
    const body = screen.getByTestId('trust-check-panel-context-body');
    expect(body).toHaveTextContent(summary);
    // The Where / When / Example list is not in the sidebar.
    expect(body).not.toHaveTextContent(/Where|When|Example/);
  });
});

describe('TrustCheckPanel — query list', () => {
  const flush = () => act(() => new Promise<void>(resolve => setTimeout(resolve, 0)));
  const recognition = (id: string, authority_id: string) => ({
    id,
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    authority_source: 'authority',
    query: { authority_id },
  });

  it('lists the queries under a Trust Check Queries heading', () => {
    render(
      <TrustCheckPanel
        {...(baseProps(AP_SLOT, { queries: [recognition('q-1', 'did:web:auth.example')] }) as any)}
      />
    );

    expect(screen.getByText('Trust Check Queries')).toBeInstanceOf(HTMLLabelElement);
    expect(screen.getByTestId('trust-check-panel-list')).toHaveClass('list-group');
    expect(screen.queryByTestId('trust-check-panel-empty-state')).toBeNull();
  });

  it('shows a ready row with its type, registry name and Authority name', async () => {
    render(
      <TrustCheckPanel
        {...(baseProps(AP_SLOT, { queries: [recognition('q-1', 'did:web:auth.example')] }) as any)}
      />
    );
    await flush();

    const row = screen.getByTestId('trust-check-panel-query-0');
    expect(row).toHaveTextContent('Query 1');
    expect(row).toHaveTextContent('Recognition');
    const type = screen.getByTestId('trust-check-panel-query-0-type');
    expect(type).toHaveClass('app-badge', 'text-bg-secondary');
    expect(type).toContainHTML('<i class="fas fa-id-badge" aria-hidden="true"></i>');
    expect(row).toHaveTextContent('Partner Registry · Payments Authority');
    expect(screen.getByTestId('trust-check-panel-query-0-authorities')).toHaveTextContent(
      /^Payments Authority$/
    );
    // One detail line only: the action and resource stay in the fullscreen editor.
    expect(row).not.toHaveTextContent('ownedAgent');
    const status = screen.getByTestId('trust-check-panel-query-0-status');
    expect(status).toHaveClass('fa-circle-check', 'text-success');
    expect(status).toHaveAttribute('aria-label', 'Ready');
  });

  it('shows an authorization row without its action and resource', async () => {
    const config = {
      queries: [
        {
          ...recognition('q-1', 'did:web:auth.example'),
          query_type: 'authorization',
          query: { authority_id: 'did:web:auth.example', action: 'issue', resource: 'payment' },
        },
      ],
    };
    render(<TrustCheckPanel {...(baseProps(AP_SLOT, config) as any)} />);
    await flush();

    const row = screen.getByTestId('trust-check-panel-query-0');
    expect(row).toHaveTextContent('Authorization');
    expect(screen.getByTestId('trust-check-panel-query-0-type')).toContainHTML(
      '<i class="fas fa-user-shield" aria-hidden="true"></i>'
    );
    expect(row).not.toHaveTextContent('payment');
  });

  it('shows the problem of an incomplete query on its row, with a warning icon', () => {
    const config = { queries: [{ id: 'q-1', trust_registry_id: '', query_type: 'recognition' }] };
    render(<TrustCheckPanel {...(baseProps(TP_SLOT, config) as any)} />);

    const status = screen.getByTestId('trust-check-panel-query-0-status');
    expect(status).toHaveClass('fa-circle-exclamation', 'text-warning');
    expect(status).toHaveAttribute('aria-label', 'Trust registry must be selected');
    expect(screen.getByTestId('trust-check-panel-query-0')).toHaveTextContent(
      'Trust registry must be selected'
    );
  });

  it('counts the listed Authorities, with their names on hover', async () => {
    const config = {
      queries: [
        {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'recognition',
          query: {
            authority_ids: ['did:web:authority-a', 'did:web:issuer.example', 'did:web:unknown'],
          },
        },
      ],
    };
    render(<TrustCheckPanel {...(baseProps(AP_SLOT, config) as any)} />);
    await flush();
    expect(screen.getByTestId('trust-check-panel-query-0-authorities')).toHaveTextContent(
      /^3 Authorities$/
    );
    expect(
      screen.getByTitle('Partner Registry · authority-A, Acme Issuer, did:web:unknown')
    ).toHaveTextContent('Partner Registry · 3 Authorities');
  });

  it('shows the first 5 of 7 queries, then "+2 more"', () => {
    const queries = Array.from({ length: 7 }, (_, i) =>
      recognition(`q-${i}`, 'did:web:auth.example')
    );
    render(<TrustCheckPanel {...(baseProps(AP_SLOT, { queries }) as any)} />);

    expect(screen.getByTestId('trust-check-panel-query-4')).toBeInTheDocument();
    expect(screen.queryByTestId('trust-check-panel-query-5')).toBeNull();
    expect(screen.getByTestId('trust-check-panel-more')).toHaveTextContent('+2 more');
  });

  it.each([
    [AP_SLOT, 'Add a query to have OPA verify the caller against a trust registry.'],
    [TP_SLOT, 'Add a query to have OPA verify the upstream agent against a trust registry.'],
  ])('shows the empty state in place of the list (%s)', (slot, copy) => {
    render(<TrustCheckPanel {...(baseProps(slot) as any)} />);

    const empty = screen.getByTestId('trust-check-panel-empty-state');
    expect(empty).toHaveTextContent('No trust checks yet');
    expect(empty).toHaveTextContent(copy);
    expect(screen.queryByTestId('trust-check-panel-list')).toBeNull();
    expect(screen.getByTestId('trust-check-panel-configure')).toBeInTheDocument();
  });

  it('opens the editor from a Configure queries link below the list', () => {
    const props = baseProps(AP_SLOT);
    render(<TrustCheckPanel {...(props as any)} />);

    const link = screen.getByTestId('trust-check-panel-configure');
    expect(link).toHaveTextContent('Configure queries');
    expect(link).toHaveClass('btn', 'btn-sm', 'btn-link', 'px-0');
    expect(link).toContainHTML('<i class="fas fa-pen-to-square me-1"></i>');
    fireEvent.click(link);
    expect(props.openFullscreenEditor).toHaveBeenCalled();
  });

  it('uses no inline styles', () => {
    const { container } = render(
      <TrustCheckPanel
        {...(baseProps(TP_SLOT, { queries: [recognition('q-1', 'did:web:auth.example')] }) as any)}
      />
    );
    expect(container.innerHTML).not.toMatch(/\sstyle=/);
  });
});

describe('TrustCheckPanel — deleted Authority', () => {
  const GONE = 'did:web:deleted-authority.example';
  const query = (id: string, authority_id: string, authority_source?: string) => ({
    id,
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    ...(authority_source ? { authority_source } : {}),
    query: { authority_id },
  });

  function renderWithRegister(
    config: Record<string, unknown>,
    authorityDids: ReadonlySet<string> | null
  ) {
    const meta = { authorityDids } as unknown as SurfaceMetaValue;
    return render(
      <SurfaceMetaProvider value={meta}>
        <TrustCheckPanel {...(baseProps(AP_SLOT, config) as any)} />
      </SurfaceMetaProvider>
    );
  }

  it('shows Configuration required with the DID while the Authority is gone', () => {
    renderWithRegister(
      { queries: [query('q-1', GONE, 'authority')] },
      new Set(['did:web:auth.example'])
    );
    const warning = screen.getByTestId('trust-check-panel-authority-missing');
    expect(warning).toHaveTextContent('Configuration required');
    expect(warning).toHaveTextContent(
      'The Authority this Trust Check uses no longer exists, so the check fails with AUTHORITY_NOT_FOUND until this is fixed.'
    );
    expect(screen.getByTestId('trust-check-panel-authority-missing-dids')).toHaveTextContent(
      `Authority DID: ${GONE}`
    );
  });

  it('names the query when the Trust Check has several', () => {
    renderWithRegister(
      {
        queries: [
          query('q-1', 'did:web:auth.example', 'authority'),
          query('q-2', GONE, 'authority'),
        ],
      },
      new Set(['did:web:auth.example'])
    );
    expect(screen.getByTestId('trust-check-panel-authority-missing-dids')).toHaveTextContent(
      `Query 2: ${GONE}`
    );
  });

  it('says nothing while the register has not loaded', () => {
    renderWithRegister({ queries: [query('q-1', GONE, 'authority')] }, null);
    expect(screen.queryByTestId('trust-check-panel-authority-missing')).toBeNull();
  });

  it('says nothing for a DID that did not come from the Authorities register', () => {
    renderWithRegister({ queries: [query('q-1', GONE, 'issuer')] }, new Set());
    expect(screen.queryByTestId('trust-check-panel-authority-missing')).toBeNull();
  });
});

describe('TrustCheckFullscreenPanel — Authority source', () => {
  const flush = () => act(() => new Promise<void>(resolve => setTimeout(resolve, 0)));

  async function openEditor(queries: unknown[]) {
    const props = { ...baseProps(TP_SLOT, { queries }), closeFullscreenEditor: jest.fn() } as any;
    render(<TrustCheckFullscreenPanel {...props} />);
    await flush();
    return props;
  }

  /** Open Add Issuers or Authorities, tick each DID in order, then Add. */
  function addAuthorities(...dids: string[]) {
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
    for (const did of dids) {
      fireEvent.click(screen.getByTestId(`trust-check-query-0-add-authority-option-${did}`));
    }
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority-confirm'));
  }

  /** Replace the stored single Authority with `did`, then Save. */
  function replaceAuthority(did: string) {
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority-0-remove'));
    addAuthorities(did);
    fireEvent.click(screen.getByTestId('trust-check-save'));
  }

  const stored = (authority_id: string, authority_source: string) => ({
    id: 'q-1',
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    authority_source,
    query: { authority_id },
  });

  it('saves authority_source "authority" beside a picked Authority', async () => {
    const { updateFields } = await openEditor([stored('did:web:issuer.example', 'issuer')]);
    replaceAuthority('did:web:auth.example');
    const [query] = updateFields.mock.calls[0][0].queries;
    expect(query.authority_source).toBe('authority');
    expect(query.query.authority_id).toBe('did:web:auth.example');
  });

  it('saves authority_source "issuer" beside a picked Issuer', async () => {
    const { updateFields } = await openEditor([stored('did:web:auth.example', 'authority')]);
    replaceAuthority('did:web:issuer.example');
    const [query] = updateFields.mock.calls[0][0].queries;
    expect(query.authority_source).toBe('issuer');
    expect(query.query.authority_id).toBe('did:web:issuer.example');
  });

  it('saves several Authorities and an Issuer, added together, each with its register', async () => {
    const { updateFields } = await openEditor([stored('did:web:authority-a', 'authority')]);
    addAuthorities('did:web:authority-b', 'did:web:authority-c', 'did:web:issuer.example');
    expect(screen.getByTestId('trust-check-query-0-authority-3')).toHaveTextContent('New');
    fireEvent.click(screen.getByTestId('trust-check-save'));
    const [query] = updateFields.mock.calls[0][0].queries;
    expect(query.query.authority_ids).toEqual([
      'did:web:authority-a',
      'did:web:authority-b',
      'did:web:authority-c',
      'did:web:issuer.example',
    ]);
    expect(query.query).not.toHaveProperty('authority_id');
    expect(query.authority_sources).toEqual({
      'did:web:authority-a': 'authority',
      'did:web:authority-b': 'authority',
      'did:web:authority-c': 'authority',
      'did:web:issuer.example': 'issuer',
    });
    expect(query).not.toHaveProperty('authority_source');
  });

  it('does not save a target leg left with no Authority', async () => {
    const { updateFields } = await openEditor([stored('did:web:authority-a', 'authority')]);
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority-0-remove'));
    fireEvent.click(screen.getByTestId('trust-check-save'));
    expect(updateFields).not.toHaveBeenCalled();
    expect(screen.getByTestId('trust-check-query-0-authority-empty')).toHaveClass('is-invalid');
  });

  it('saves a single authority_id again once the extra rows are removed', async () => {
    const { updateFields } = await openEditor([stored('did:web:authority-a', 'authority')]);
    addAuthorities('did:web:authority-b');
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority-0-remove'));
    fireEvent.click(screen.getByTestId('trust-check-save'));
    const [query] = updateFields.mock.calls[0][0].queries;
    expect(query.query).toEqual({ authority_id: 'did:web:authority-b' });
    expect(query.authority_source).toBe('authority');
    expect(query).not.toHaveProperty('authority_sources');
  });

  it('opens a stored list of Authorities row by row, with nothing to save', async () => {
    const listed = {
      id: 'q-1',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      authority_sources: { 'did:web:authority-b': 'authority', 'did:web:issuer.example': 'issuer' },
      query: { authority_ids: ['did:web:authority-b', 'did:web:issuer.example'] },
    };
    const { updateFields } = await openEditor([listed]);
    expect(screen.getByTestId('trust-check-query-0-authority-0')).toHaveTextContent('authority-B');
    expect(screen.getByTestId('trust-check-query-0-authority-1')).toHaveTextContent('Acme Issuer');
    expect(screen.getByTestId('trust-check-save')).toBeDisabled();
    expect(updateFields).not.toHaveBeenCalled();
  });

  it('saves queries naming more than 25 Authorities in total', async () => {
    const listOf = (id: string, count: number) => ({
      id,
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      query: { authority_ids: Array.from({ length: count }, (_, i) => `did:web:${id}-${i}`) },
    });
    const { updateFields } = await openEditor([
      listOf('first', 20),
      listOf('second', 6),
      stored('did:web:authority-a', 'authority'),
    ]);
    fireEvent.click(screen.getByTestId('trust-check-editor-query-2'));
    fireEvent.click(screen.getByTestId('trust-check-editor-remove-query-button'));
    expect(screen.getByTestId('trust-check-add-query')).toBeEnabled();
    fireEvent.click(screen.getByTestId('trust-check-save'));
    expect(updateFields.mock.calls[0][0].queries).toHaveLength(2);
  });

  it('flags a deleted Authority once the register has loaded', async () => {
    await openEditor([stored('did:web:deleted-authority.example', 'authority')]);
    expect(screen.getByTestId('trust-check-query-0-authority-missing')).toHaveTextContent(
      'did:web:deleted-authority.example'
    );
  });
});

describe('TrustCheckFullscreenPanel — layout', () => {
  const flush = () => act(() => new Promise<void>(resolve => setTimeout(resolve, 0)));

  const recognition = (id: string, trust_registry_id = 'tr-1') => ({
    id,
    trust_registry_id,
    query_type: 'recognition',
    authority_source: 'authority',
    query: { authority_id: 'did:web:auth.example' },
  });

  async function openEditor(slotId: string, queries: unknown[]) {
    const props = { ...baseProps(slotId, { queries }), closeFullscreenEditor: jest.fn() } as any;
    render(<TrustCheckFullscreenPanel {...props} />);
    await flush();
    return props;
  }

  it('lists every query with its status and opens the first one', async () => {
    await openEditor(AP_SLOT, [recognition('q-1'), recognition('q-2', '')]);
    expect(screen.getByTestId('trust-check-editor-query-0')).toHaveAttribute(
      'aria-current',
      'true'
    );
    expect(screen.getByTestId('trust-check-editor-query-0')).toHaveTextContent('Partner Registry');
    expect(screen.getByTestId('trust-check-editor-query-0-status')).toHaveAttribute(
      'aria-label',
      'Ready'
    );
    expect(screen.getByTestId('trust-check-editor-query-1-status')).toHaveClass('text-warning');
    expect(screen.getByTestId('trust-check-editor-query-settings')).toHaveTextContent('Query 1');
    expect(screen.getByTestId('trust-check-fullscreen-count')).toHaveTextContent('2 queries');
    expect(screen.getByTestId('trust-check-fullscreen-leg-pill')).toHaveTextContent('Caller leg');
  });

  it('shows the settings of the query a row selects', async () => {
    await openEditor(AP_SLOT, [recognition('q-1'), recognition('q-2')]);
    fireEvent.click(screen.getByTestId('trust-check-editor-query-1'));
    expect(screen.getByTestId('trust-check-editor-query-1')).toHaveAttribute(
      'aria-current',
      'true'
    );
    expect(screen.getByTestId('trust-check-editor-query-0')).not.toHaveAttribute('aria-current');
    expect(screen.getByTestId('trust-check-editor-query-settings')).toHaveTextContent('Query 2');
    expect(screen.getByTestId('trust-check-query-1-form')).toBeInTheDocument();
  });

  it('adds a query and selects it, marking the draft unsaved', async () => {
    await openEditor(AP_SLOT, [recognition('q-1')]);
    expect(screen.queryByTestId('trust-check-fullscreen-unsaved')).toBeNull();
    fireEvent.click(screen.getByTestId('trust-check-add-query'));
    expect(screen.getByTestId('trust-check-editor-query-1')).toHaveAttribute(
      'aria-current',
      'true'
    );
    expect(screen.getByTestId('trust-check-fullscreen-unsaved')).toHaveTextContent(
      'Unsaved changes'
    );
  });

  it('switches the record type with the toggle', async () => {
    const { updateFields } = await openEditor(AP_SLOT, [recognition('q-1')]);
    expect(screen.getByTestId('trust-check-query-0-type-recognition')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-type-authorization'));
    expect(screen.getByTestId('trust-check-query-0-type-authorization')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(screen.getByTestId('trust-check-editor-query-0-type')).toHaveTextContent(
      'Authorization'
    );
    fireEvent.change(screen.getByTestId('trust-check-query-0-action'), {
      target: { value: 'issue' },
    });
    fireEvent.change(screen.getByTestId('trust-check-query-0-resource'), {
      target: { value: 'credential:X' },
    });
    fireEvent.click(screen.getByTestId('trust-check-save'));
    expect(updateFields.mock.calls[0][0].queries[0].query_type).toBe('authorization');
  });

  it('removes the selected query and selects the one before it', async () => {
    await openEditor(AP_SLOT, [recognition('q-1'), recognition('q-2'), recognition('q-3')]);
    fireEvent.click(screen.getByTestId('trust-check-editor-query-2'));
    fireEvent.click(screen.getByTestId('trust-check-editor-remove-query-button'));
    expect(screen.queryByTestId('trust-check-editor-query-2')).toBeNull();
    expect(screen.getByTestId('trust-check-editor-query-1')).toHaveAttribute(
      'aria-current',
      'true'
    );
    expect(screen.getByTestId('trust-check-editor-query-settings')).toHaveTextContent('Query 2');
  });

  it('opens the first query that blocks Save', async () => {
    const { updateFields } = await openEditor(AP_SLOT, [
      recognition('q-1'),
      { ...recognition('q-2'), query_type: 'authorization' },
    ]);
    fireEvent.click(screen.getByTestId('trust-check-add-query'));
    fireEvent.click(screen.getByTestId('trust-check-editor-query-0'));
    fireEvent.click(screen.getByTestId('trust-check-save'));
    expect(updateFields).not.toHaveBeenCalled();
    expect(screen.getByTestId('trust-check-editor-query-settings')).toHaveTextContent('Query 2');
    expect(screen.getByTestId('trust-check-query-1-action')).toHaveClass('is-invalid');
  });

  it('states the leg and its OPA path in one line, with no Where / When block', async () => {
    await openEditor(TP_SLOT, [recognition('q-1')]);
    const intro = screen.getByTestId('trust-check-fullscreen-leg');
    expect(intro).toHaveTextContent('input.trust_check_results.target[]');
    expect(intro).toHaveTextContent('Applies to this Transit Point only.');
    expect(screen.queryByText('Where, when and an example')).toBeNull();
  });
});
