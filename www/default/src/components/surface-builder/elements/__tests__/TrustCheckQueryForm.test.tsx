import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import TrustCheckQueryForm from '../trust-check/TrustCheckQueryForm';
import type { TrustCheckQueryConfig } from '../trust-check/definition';

const AGENT_IDENTITY_ISSUER = '{{ input.agent.identity_issuer_did }}';

function baseProps(overrides: Partial<Parameters<typeof TrustCheckQueryForm>[0]> = {}) {
  const emptyQuery: TrustCheckQueryConfig = {
    id: 'q-1',
    trust_registry_id: '',
    query_type: 'authorization',
    query: {},
  };
  return {
    queryConfig: emptyQuery,
    index: 0,
    isApMa: true,
    registries: [],
    issuers: [],
    authorities: [],
    loadError: null,
    updateQueryAt: jest.fn(),
    updateQuerySubField: jest.fn(),
    replaceQueryAt: jest.fn(),
    updateEntityAt: jest.fn(),
    handleQueryTypeChangeAt: jest.fn(),
    ...overrides,
  } as Parameters<typeof TrustCheckQueryForm>[0];
}

// TrustCheckQueryForm renders a react-router <Link> in its "no trust
// registries configured" hint; every test render therefore needs a
// Router context.
function renderForm(props: Parameters<typeof TrustCheckQueryForm>[0]) {
  return render(
    <MemoryRouter>
      <TrustCheckQueryForm {...props} />
    </MemoryRouter>
  );
}

const ISSUER = { id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' };
const AUTHORITY = { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' };
const GONE = 'did:web:deleted-authority.example';

const single = (authority_id: string, authority_source?: 'authority' | 'issuer' | 'did') =>
  ({
    id: 'q-1',
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    ...(authority_source ? { authority_source } : {}),
    query: { authority_id },
  }) as TrustCheckQueryConfig;

const listed = (authority_ids: string[], sources: Record<string, string> = {}) =>
  ({
    id: 'q-1',
    trust_registry_id: 'tr-1',
    query_type: 'recognition',
    authority_sources: sources,
    query: { authority_ids },
  }) as TrustCheckQueryConfig;

/** Open Add Issuers or Authorities, tick each option (by DID or request key), then Add. */
function addAuthorities(...keys: string[]) {
  fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
  for (const key of keys) {
    fireEvent.click(screen.getByTestId(`trust-check-query-0-add-authority-option-${key}`));
  }
  fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority-confirm'));
}

describe('TrustCheckQueryForm — Authorities on the caller leg', () => {
  it('uses the agent identity credential issuer while no Authority is listed', () => {
    renderForm(baseProps({ saveAttempted: true }));
    expect(screen.getByTestId('trust-check-query-0-authority-count')).toHaveTextContent(
      'Agent identity credential issuer (default)'
    );
    expect(screen.getByTestId('trust-check-query-0-authority-empty')).not.toHaveClass('is-invalid');
  });

  it('offers the request values, then the Authorities and the Issuers', () => {
    renderForm(baseProps({ issuers: [ISSUER] as any, authorities: [AUTHORITY] as any }));
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
    const menu = within(screen.getByTestId('trust-check-query-0-add-authority-menu'));
    expect(menu.getByText('From the request · caller leg')).toBeInTheDocument();
    expect(menu.getByText('Agent identity credential issuer')).toBeInTheDocument();
    expect(menu.getByText('Sending gateway DID (fabric-inbound)')).toBeInTheDocument();
    expect(menu.getByText('Authorities')).toBeInTheDocument();
    expect(menu.getByText('Payments Authority')).toBeInTheDocument();
    expect(menu.getByText('Issuers')).toBeInTheDocument();
    expect(menu.getByText('Acme Inc')).toBeInTheDocument();
  });

  it('adds the ticked ones in the order ticked, each with its register', () => {
    const replaceQueryAt = jest.fn();
    renderForm(
      baseProps({ replaceQueryAt, issuers: [ISSUER] as any, authorities: [AUTHORITY] as any })
    );
    addAuthorities(ISSUER.did, AUTHORITY.did);
    const [index, next] = replaceQueryAt.mock.calls[0];
    expect(index).toBe(0);
    expect(next.query.authority_ids).toEqual([ISSUER.did, AUTHORITY.did]);
    expect(next.authority_sources).toEqual({
      [ISSUER.did]: 'issuer',
      [AUTHORITY.did]: 'authority',
    });
    expect(screen.getByTestId('trust-check-query-0-authority-added')).toHaveTextContent(
      'Added 2 at the end: Acme Inc, Payments Authority.'
    );
  });

  it('adds one picked Authority as authority_id with its source', () => {
    const replaceQueryAt = jest.fn();
    renderForm(baseProps({ replaceQueryAt, authorities: [AUTHORITY] as any }));
    addAuthorities(AUTHORITY.did);
    const [, next] = replaceQueryAt.mock.calls[0];
    expect(next.query).toEqual({ authority_id: AUTHORITY.did });
    expect(next.authority_source).toBe('authority');
  });

  it('adds a request value with no source', () => {
    const replaceQueryAt = jest.fn();
    renderForm(baseProps({ replaceQueryAt }));
    addAuthorities('agent-identity-issuer');
    const [, next] = replaceQueryAt.mock.calls[0];
    expect(next.query).toEqual({ authority_id: AGENT_IDENTITY_ISSUER });
    expect(next).not.toHaveProperty('authority_source');
  });

  it('shows a listed value ticked and locked with its row', () => {
    renderForm(
      baseProps({
        authorities: [AUTHORITY] as any,
        queryConfig: single(AUTHORITY.did, 'authority'),
      })
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
    const option = screen.getByTestId(`trust-check-query-0-add-authority-option-${AUTHORITY.did}`);
    expect(option).toBeChecked();
    expect(option).toBeDisabled();
    expect(screen.queryByText('Row 1')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-add-authority-confirm')).toBeDisabled();
  });

  it('marks a leftover template invalid after a save attempt', () => {
    renderForm(
      baseProps({ saveAttempted: true, queryConfig: single('{{ input.agent.provider_did }}') })
    );
    const row = screen.getByTestId('trust-check-query-0-authority-0');
    expect(row).toHaveTextContent('Legacy template (from JSON API)');
    expect(row).toHaveClass('is-invalid');
  });
});

describe('TrustCheckQueryForm — Authorities on the target leg', () => {
  it('offers no request values', () => {
    renderForm(baseProps({ isApMa: false, authorities: [AUTHORITY] as any }));
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
    expect(screen.queryByText('From the request · caller leg')).toBeNull();
    expect(screen.getByText('Payments Authority')).toBeInTheDocument();
  });

  it('flags an empty list after a save attempt', () => {
    renderForm(baseProps({ isApMa: false, authorities: [AUTHORITY] as any, saveAttempted: true }));
    expect(screen.getByTestId('trust-check-query-0-authority-empty')).toHaveClass('is-invalid');
  });

  it('says where to add an Issuer or Authority when none is configured', () => {
    renderForm(baseProps({ isApMa: false }));
    expect(screen.queryByTestId('trust-check-query-0-add-authority')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-authority-locked')).toHaveTextContent(
      'No Issuers or Authorities configured'
    );
    expect(screen.getByTestId('trust-check-query-0-authority-add-issuer-link')).toHaveAttribute(
      'target',
      '_blank'
    );
    expect(screen.getByTestId('trust-check-query-0-authority-add-authority-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });
});

describe('TrustCheckQueryForm — the Authority table', () => {
  const A = 'did:web:authority-a';
  const B = 'did:web:authority-b';
  const C = 'did:web:authority-c';
  const REGISTER = [
    { id: 'a-a', name: 'authority-A', did: A },
    { id: 'a-b', name: 'authority-B', did: B },
    { id: 'a-c', name: 'authority-C', did: C },
  ];
  const three = listed([A, B, C], { [A]: 'authority', [B]: 'authority', [C]: 'authority' });

  it('lists each Authority in result order with its register', () => {
    renderForm(baseProps({ authorities: REGISTER as any, queryConfig: three }));
    expect(screen.getByTestId('trust-check-query-0-authority-count')).toHaveTextContent(
      '3 Authorities'
    );
    expect(screen.getByTestId('trust-check-query-0-authority-1')).toHaveTextContent('authority-B');
    expect(screen.getByTestId('trust-check-query-0-authority-1')).toHaveTextContent('Authority');
  });

  it('removes a row', () => {
    const replaceQueryAt = jest.fn();
    renderForm(baseProps({ replaceQueryAt, authorities: REGISTER as any, queryConfig: three }));
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority-0-remove'));
    expect(replaceQueryAt.mock.calls[0][1].query.authority_ids).toEqual([B, C]);
  });

  it('marks the ones added since the editor opened as New', () => {
    renderForm(
      baseProps({
        authorities: REGISTER as any,
        queryConfig: three,
        baselineDids: new Set([A, B]),
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority-2')).toHaveTextContent('New');
    expect(screen.getByTestId('trust-check-query-0-authority-0')).not.toHaveTextContent('New');
  });

  it('offers a filter once the list passes eight', () => {
    const many = Array.from({ length: 9 }, (_, i) => `did:web:auth-${i}`);
    renderForm(baseProps({ queryConfig: listed(many) }));
    const filter = screen.getByTestId('trust-check-query-0-authority-filter');
    fireEvent.change(filter, { target: { value: 'auth-4' } });
    expect(screen.getByTestId('trust-check-query-0-authority-4')).toBeInTheDocument();
    expect(screen.queryByTestId('trust-check-query-0-authority-0')).toBeNull();
  });

  it('marks a stored empty row invalid after a save attempt', () => {
    renderForm(
      baseProps({
        authorities: REGISTER as any,
        queryConfig: listed([A, ''], { [A]: 'authority' }),
        saveAttempted: true,
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority-1')).toHaveClass('is-invalid');
    expect(screen.getByTestId('trust-check-query-0-authority-0')).not.toHaveClass('is-invalid');
  });
});

describe('TrustCheckQueryForm — deleted Authority', () => {
  it('shows it in its row with the Configuration required warning', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [ISSUER] as any,
        authorities: [AUTHORITY] as any,
        queryConfig: single(GONE, 'authority'),
      })
    );
    const row = screen.getByTestId('trust-check-query-0-authority-0');
    expect(row).toHaveTextContent('Deleted Authority');
    expect(row).toHaveClass('is-invalid');
    const warning = screen.getByTestId('trust-check-query-0-authority-missing');
    expect(warning).toHaveAttribute('role', 'alert');
    expect(warning).toHaveTextContent('Configuration required');
    expect(warning).toHaveTextContent('AUTHORITY_NOT_FOUND');
    expect(warning).toHaveTextContent(GONE);
    expect(
      screen.getByTestId('trust-check-query-0-authority-missing-add-authority-link')
    ).toHaveAttribute('href', '/authorities/new');
  });

  it('names its row when the query lists several', () => {
    renderForm(
      baseProps({
        authorities: [AUTHORITY] as any,
        queryConfig: listed([AUTHORITY.did, GONE], {
          [AUTHORITY.did]: 'authority',
          [GONE]: 'authority',
        }),
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority-missing-dids')).toHaveTextContent(
      `Row 2: ${GONE}`
    );
  });

  it('does not warn while the Authorities register has not loaded', () => {
    renderForm(
      baseProps({
        isApMa: false,
        authorities: [AUTHORITY] as any,
        authoritiesLoaded: false,
        queryConfig: single(GONE, 'authority'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-missing')).toBeNull();
  });

  it('shows a DID from neither register as a custom DID, with no warning', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [ISSUER] as any,
        authorities: [AUTHORITY] as any,
        queryConfig: single(GONE, 'did'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-missing')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-authority-0')).toHaveTextContent(
      'Custom DID (from JSON API)'
    );
  });
});

describe('TrustCheckQueryForm — Action and Resource', () => {
  it('marks Action and Resource as required (with visible asterisks) for an authorization query but does not flash is-invalid before Save', () => {
    renderForm(
      baseProps({
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: {},
        },
      })
    );

    const action = screen.getByTestId('trust-check-query-0-action');
    const resource = screen.getByTestId('trust-check-query-0-resource');
    expect(action).toHaveAttribute('required');
    expect(resource).toHaveAttribute('required');
    // is-invalid is deferred until the operator clicks Save.
    expect(action).not.toHaveClass('is-invalid');
    expect(resource).not.toHaveClass('is-invalid');
  });

  it('surfaces is-invalid on empty Action and Resource once saveAttempted flips true', () => {
    renderForm(
      baseProps({
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: {},
        },
        saveAttempted: true,
      })
    );

    expect(screen.getByTestId('trust-check-query-0-action')).toHaveClass('is-invalid');
    expect(screen.getByTestId('trust-check-query-0-resource')).toHaveClass('is-invalid');
  });

  it('leaves Action and Resource optional for a recognition query', () => {
    renderForm(
      baseProps({
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'recognition',
          query: {},
        },
      })
    );

    const action = screen.getByTestId('trust-check-query-0-action');
    const resource = screen.getByTestId('trust-check-query-0-resource');
    expect(action).not.toHaveAttribute('required');
    expect(resource).not.toHaveAttribute('required');
    expect(action).not.toHaveClass('is-invalid');
    expect(resource).not.toHaveClass('is-invalid');
  });

  it('does not render a Name input (editor removed; wire field still round-trips)', () => {
    renderForm(baseProps());

    expect(screen.queryByTestId('trust-check-query-0-name')).toBeNull();
    expect(screen.queryByLabelText(/Name/i)).toBeNull();
  });
});
