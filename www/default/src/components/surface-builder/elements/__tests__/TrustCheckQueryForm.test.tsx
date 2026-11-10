import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import TrustCheckQueryForm from '../trust-check/TrustCheckQueryForm';
import type { TrustCheckQueryConfig } from '../trust-check/definition';

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
    updateAuthorityAt: jest.fn(),
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

describe('TrustCheckQueryForm — Authority rendering', () => {
  it('renders an Issuer/Authority picker on the caller leg grouping Departments and Authorities', () => {
    renderForm(
      baseProps({
        isApMa: true,
        issuers: [{ id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' }] as any,
        authorities: [
          { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' },
        ] as any,
      })
    );

    // The Authority picker toggle is present and the locked textbox is not.
    const toggle = screen.getByTestId('trust-check-query-0-authority');
    expect(toggle).toBeInTheDocument();
    expect(screen.queryByTestId('trust-check-query-0-authority-locked')).toBeNull();
    // Opening the menu reveals the grouped register entries — no more
    // "caller's Provider DID (default)" option.
    fireEvent.click(toggle);
    expect(screen.getByText('Issuers')).toBeInTheDocument();
    expect(screen.getByText('Authorities')).toBeInTheDocument();
    expect(screen.getByText(/Acme Inc/)).toBeInTheDocument();
    expect(screen.getByText('Payments Authority')).toBeInTheDocument();
  });

  it('writes the literal Issuer DID verbatim when an Issuer is selected on the caller leg', () => {
    const updateAuthorityAt = jest.fn();
    renderForm(
      baseProps({
        isApMa: true,
        updateAuthorityAt,
        issuers: [{ id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' }] as any,
        authorities: [],
      })
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority'));
    fireEvent.click(screen.getByText('Acme Inc'));
    expect(updateAuthorityAt).toHaveBeenCalledWith(0, 'did:web:acme.example', 'issuer');
  });

  it('renders the verified-issuer default picker on the caller leg even when no Issuers or Authorities are configured (no degenerate locked textbox on the caller leg)', () => {
    renderForm(baseProps({ isApMa: true, issuers: [], authorities: [] }));
    expect(screen.queryByTestId('trust-check-query-0-authority-locked')).toBeNull();
    const toggle = screen.getByTestId('trust-check-query-0-authority');
    expect(toggle).toBeInTheDocument();
    expect(toggle).toHaveTextContent(/Agent identity credential issuer \(default\)/i);
  });

  it('surfaces a stored legacy template as a locked "from JSON API" option on the caller leg', () => {
    renderForm(
      baseProps({
        isApMa: true,
        issuers: [],
        authorities: [],
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: { authority_id: '{{ input.agent.provider_did }}' },
        },
      })
    );

    const toggle = screen.getByTestId('trust-check-query-0-authority');
    expect(toggle).toHaveTextContent(/Legacy template \(from JSON API\)/i);
  });

  it('leaves the caller-leg Authority valid when nothing is picked (blank defaults to the verified issuer) even after saveAttempted', () => {
    renderForm(
      baseProps({
        isApMa: true,
        issuers: [{ id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' }] as any,
        authorities: [],
        saveAttempted: true,
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority')).not.toHaveClass('is-invalid');
  });

  it('marks the caller-leg Authority invalid after saveAttempted when a non-default leftover template is stored', () => {
    renderForm(
      baseProps({
        isApMa: true,
        issuers: [{ id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' }] as any,
        authorities: [],
        saveAttempted: true,
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: { authority_id: '{{ input.agent.provider_did }}' },
        },
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority')).toHaveClass('is-invalid');
  });

  it('renders a locked read-only textbox on the target leg when no Issuers or Authorities are configured and nothing custom is stored', () => {
    renderForm(baseProps({ isApMa: false, issuers: [], authorities: [] }));
    expect(screen.queryByTestId('trust-check-query-0-authority')).toBeNull();
    const locked = screen.getByTestId('trust-check-query-0-authority-locked');
    expect(locked).toHaveAttribute('readonly');
    expect(locked).toBeDisabled();
    expect(locked).toHaveValue('No Issuers or Authorities configured');
    expect(screen.getByTestId('trust-check-query-0-authority-add-issuer-link')).toHaveAttribute(
      'target',
      '_blank'
    );
    expect(screen.getByTestId('trust-check-query-0-authority-add-authority-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });

  it('renders an Issuer/Authority picker on the target leg grouping Departments and Authorities', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [{ id: 'd-1', name: 'Acme Dept', did: 'did:web:acme.example' }] as any,
        authorities: [
          { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' },
        ] as any,
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-locked')).toBeNull();
    const toggle = screen.getByTestId('trust-check-query-0-authority');
    expect(toggle).toBeInTheDocument();
    fireEvent.click(toggle);
    // Group headers plus the two register entries are visible.
    expect(screen.getByText('Issuers')).toBeInTheDocument();
    expect(screen.getByText('Authorities')).toBeInTheDocument();
    expect(screen.getByText('Acme Dept')).toBeInTheDocument();
    expect(screen.getByText('Payments Authority')).toBeInTheDocument();
  });

  it('writes the literal Issuer DID verbatim when an Issuer is selected on the target leg', () => {
    const updateAuthorityAt = jest.fn();
    renderForm(
      baseProps({
        isApMa: false,
        updateAuthorityAt,
        issuers: [{ id: 'd-1', name: 'Acme Dept', did: 'did:web:acme.example' }] as any,
        authorities: [],
      })
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority'));
    fireEvent.click(screen.getByText('Acme Dept'));
    expect(updateAuthorityAt).toHaveBeenCalledWith(0, 'did:web:acme.example', 'issuer');
  });

  it('surfaces a stored legacy template as a locked "from JSON API" option on the target leg', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [{ id: 'd-1', name: 'Acme Dept', did: 'did:web:acme.example' }] as any,
        authorities: [],
        queryConfig: {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          query: { authority_id: '{{ input.agent.provider_did }}' },
        },
      })
    );
    const toggle = screen.getByTestId('trust-check-query-0-authority');
    // The locked custom option's label renders on the toggle.
    expect(toggle).toHaveTextContent(/Legacy template \(from JSON API\)/i);
  });

  it('marks the target-leg Authority invalid once saveAttempted flips true and nothing is picked', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [{ id: 'd-1', name: 'Acme Dept', did: 'did:web:acme.example' }] as any,
        authorities: [],
        saveAttempted: true,
      })
    );
    expect(screen.getByTestId('trust-check-query-0-authority')).toHaveClass('is-invalid');
  });

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

describe('TrustCheckQueryForm — Authority source', () => {
  const AUTHORITY = { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' };
  const ISSUER = { id: 'd-1', name: 'Acme Inc', did: 'did:web:acme.example' };
  const GONE = 'did:web:deleted-authority.example';

  const storedQuery = (authority_id: string, authority_source?: 'authority' | 'issuer' | 'did') =>
    ({
      id: 'q-1',
      trust_registry_id: 'tr-1',
      query_type: 'recognition',
      ...(authority_source ? { authority_source } : {}),
      query: { authority_id },
    }) as TrustCheckQueryConfig;

  it('writes authority_source "authority" when an Authority is picked', () => {
    const updateAuthorityAt = jest.fn();
    renderForm(
      baseProps({
        isApMa: false,
        updateAuthorityAt,
        issuers: [ISSUER] as any,
        authorities: [AUTHORITY] as any,
      })
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority'));
    fireEvent.click(screen.getByText('Payments Authority'));
    expect(updateAuthorityAt).toHaveBeenCalledWith(0, AUTHORITY.did, 'authority');
  });

  it('writes no authority_source when the caller-leg template default is picked', () => {
    const updateAuthorityAt = jest.fn();
    renderForm(
      baseProps({
        isApMa: true,
        updateAuthorityAt,
        authorities: [AUTHORITY] as any,
        queryConfig: storedQuery(AUTHORITY.did, 'authority'),
      })
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-authority'));
    fireEvent.click(screen.getByText('Agent identity credential issuer (default)'));
    expect(updateAuthorityAt).toHaveBeenCalledWith(
      0,
      '{{ input.agent.identity_issuer_did }}',
      undefined
    );
  });

  it('shows a deleted Authority as locked and invalid, with the Configuration required warning', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [ISSUER] as any,
        authorities: [AUTHORITY] as any,
        queryConfig: storedQuery(GONE, 'authority'),
      })
    );
    const toggle = screen.getByTestId('trust-check-query-0-authority');
    expect(toggle).toHaveTextContent('Deleted Authority');
    expect(toggle).toHaveClass('is-invalid');
    const warning = screen.getByTestId('trust-check-query-0-authority-missing');
    expect(warning).toHaveAttribute('role', 'alert');
    expect(warning).toHaveTextContent('Configuration required');
    expect(warning).toHaveTextContent('AUTHORITY_NOT_FOUND');
    expect(warning).toHaveTextContent(GONE);
    expect(
      screen.getByTestId('trust-check-query-0-authority-missing-add-authority-link')
    ).toHaveAttribute('href', '/authorities/new');
  });

  it('shows the deleted Authority on a target leg with no register entries left', () => {
    renderForm(
      baseProps({
        isApMa: false,
        authorities: [],
        queryConfig: storedQuery(GONE, 'authority'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-locked')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-authority-missing')).toBeInTheDocument();
  });

  it('does not warn while the Authorities register has not loaded', () => {
    renderForm(
      baseProps({
        isApMa: false,
        authorities: [],
        authoritiesLoaded: false,
        queryConfig: storedQuery(GONE, 'authority'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-missing')).toBeNull();
  });

  it('does not warn for a DID that is not from the Authorities register', () => {
    renderForm(
      baseProps({
        isApMa: false,
        issuers: [ISSUER] as any,
        authorities: [AUTHORITY] as any,
        queryConfig: storedQuery(GONE, 'did'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-missing')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-authority')).toHaveTextContent(
      'Custom DID (from JSON API)'
    );
  });

  it('does not warn while the register still has the Authority', () => {
    renderForm(
      baseProps({
        isApMa: false,
        authorities: [AUTHORITY] as any,
        queryConfig: storedQuery(AUTHORITY.did, 'authority'),
      })
    );
    expect(screen.queryByTestId('trust-check-query-0-authority-missing')).toBeNull();
    expect(screen.getByTestId('trust-check-query-0-authority')).toHaveTextContent(
      'Payments Authority'
    );
  });
});
