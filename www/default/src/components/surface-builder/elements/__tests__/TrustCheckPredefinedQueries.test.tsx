import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import TrustCheckQueryForm from '../trust-check/TrustCheckQueryForm';
import {
  applyPresetToQuery,
  matchCatalogueByTuple,
  type PredefinedTrustCheckQuery,
  type TrustCheckQueryConfig,
} from '../trust-check/definition';

const Q1: PredefinedTrustCheckQuery = {
  id: 'agent-policy-q1',
  name: 'Agent recognised by Provider',
  description: 'Does the Provider recognise this agent as one of its owned agents?',
  query_type: 'recognition',
  query: {
    authority_id: '{{ input.agent.provider_did }}',
    entity_id: '{{ input.agent.did }}',
    action: 'is',
    resource: 'ownedAgent',
  },
  origin: 'builtin',
};

const Q2: PredefinedTrustCheckQuery = {
  id: 'agent-policy-q2',
  name: 'Provider authorised to register agents',
  description: 'Is the Provider authorised by its higher Authority to register agents?',
  query_type: 'authorization',
  query: {
    authority_id: '{{ input.agent.authority_did }}',
    entity_id: '{{ input.agent.provider_did }}',
    action: 'register',
    resource: 'agents',
  },
  origin: 'builtin',
};

const CATALOGUE: PredefinedTrustCheckQuery[] = [Q1, Q2];

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

describe('matchCatalogueByTuple', () => {
  it('returns the catalogue entry whose tuple matches the current query byte-for-byte', () => {
    const q: TrustCheckQueryConfig = {
      id: 'q',
      trust_registry_id: 'tr',
      query_type: 'recognition',
      query: {
        authority_id: '{{ input.agent.provider_did }}',
        entity_id: '{{ input.agent.did }}',
        action: 'is',
        resource: 'ownedAgent',
      },
    };
    expect(matchCatalogueByTuple(q, CATALOGUE)?.id).toBe('agent-policy-q1');
  });

  it('returns null when the tuple diverges by even one character (strict literal comparison)', () => {
    const q: TrustCheckQueryConfig = {
      id: 'q',
      trust_registry_id: 'tr',
      query_type: 'recognition',
      query: {
        authority_id: '{{ input.agent.provider_did }}',
        entity_id: '{{ input.agent.did }}',
        action: 'is',
        resource: 'OWNEDAGENT', // one character off
      },
    };
    expect(matchCatalogueByTuple(q, CATALOGUE)).toBeNull();
  });

  it('does not match a fresh authorization element to any recognition-family preset', () => {
    const fresh: TrustCheckQueryConfig = {
      id: 'q',
      trust_registry_id: '',
      query_type: 'authorization',
      query: {},
    };
    expect(matchCatalogueByTuple(fresh, CATALOGUE)).toBeNull();
  });
});

describe('applyPresetToQuery', () => {
  it('writes the catalogue tuple verbatim so save round-trips byte-identically', () => {
    const draft: TrustCheckQueryConfig = {
      id: 'q-1',
      trust_registry_id: 'tr-1',
      query_type: 'authorization',
      name: 'label',
      query: { authority_id: 'stale', entity_id: 'stale' },
    };
    const next = applyPresetToQuery(draft, Q1);
    expect(next.query_type).toBe('recognition');
    expect(next.query?.authority_id).toBe('{{ input.agent.provider_did }}');
    expect(next.query?.entity_id).toBe('{{ input.agent.did }}');
    expect(next.query?.action).toBe('is');
    expect(next.query?.resource).toBe('ownedAgent');
    expect(next.id).toBe('q-1');
    expect(next.trust_registry_id).toBe('tr-1');
    expect(next.name).toBe('label');
    expect(matchCatalogueByTuple(next, CATALOGUE)?.id).toBe('agent-policy-q1');
  });
});

describe('TrustCheckQueryForm — Entity ID subject-picker dropdown (Fix 1)', () => {
  it('selects the default subject (agent DID) when entity_id is absent', () => {
    renderForm(baseProps());
    // With the default subject selected, the toggle shows the "Agent DID (default)" label.
    const toggle = screen.getByTestId('trust-check-query-0-entity');
    expect(toggle).toHaveTextContent(/agent DID/i);
    expect(toggle).toHaveTextContent(/\(default\)/i);
  });

  it('selects the matching named subject when a known template is stored', () => {
    renderForm(
      baseProps({
        queryConfig: {
          id: 'q',
          trust_registry_id: 'tr',
          query_type: 'authorization',
          query: { entity_id: '{{ input.extension_identity.did }}' },
        },
      })
    );
    // The toggle displays the gateway-managed identity subject.
    expect(screen.getByTestId('trust-check-query-0-entity')).toHaveTextContent(
      /gateway's managed-identity DID/i
    );
  });

  it('surfaces a stored literal DID as an inline Custom (from JSON API) option', () => {
    renderForm(
      baseProps({
        queryConfig: {
          id: 'q',
          trust_registry_id: 'tr',
          query_type: 'authorization',
          query: { entity_id: 'did:web:concrete.example' },
        },
      })
    );
    const toggle = screen.getByTestId('trust-check-query-0-entity');
    // The toggle shows the Custom label when a custom value is stored.
    expect(toggle).toHaveTextContent(/Custom \(from JSON API\)/);
    // Opening the menu reveals the disabled Custom option carrying the raw DID as its subheader.
    fireEvent.click(toggle);
    const customOption = screen.getByTestId('trust-check-query-0-entity-option-__custom__');
    expect(customOption).toBeDisabled();
    expect(customOption).toHaveTextContent(/Custom \(from JSON API\)/);
    expect(customOption).toHaveTextContent(/did:web:concrete\.example/);
  });

  it('writes the wire template of the chosen named subject when the operator picks the managed-identity DID', () => {
    const updateEntityAt = jest.fn();
    renderForm(baseProps({ updateEntityAt }));
    const toggle = screen.getByTestId('trust-check-query-0-entity');
    fireEvent.click(toggle);
    fireEvent.click(screen.getByTestId('trust-check-query-0-entity-option-extension-identity'));
    expect(updateEntityAt).toHaveBeenCalledWith(0, '{{ input.extension_identity.did }}');
  });
});
