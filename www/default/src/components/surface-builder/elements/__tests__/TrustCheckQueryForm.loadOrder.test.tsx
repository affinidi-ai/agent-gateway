import { trustCheckDefinition } from '../trust-check/definition';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import TrustCheckQueryForm from '../trust-check/TrustCheckQueryForm';
import type { TrustCheckQueryConfig } from '../trust-check/definition';

const AUTHORITY = { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' };

const storedQuery = {
  id: 'q-1',
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  authority_source: 'authority',
  query: { authority_id: AUTHORITY.did },
} as TrustCheckQueryConfig;

describe('TrustCheckQueryForm loaded after the Trust Check definition', () => {
  it('still writes no authority_source when the caller-leg template default is picked', () => {
    expect(trustCheckDefinition.type).toBe('trust-check');
    const setAuthoritiesAt = jest.fn();
    render(
      <MemoryRouter>
        <TrustCheckQueryForm
          queryConfig={storedQuery}
          index={0}
          isApMa
          registries={[]}
          issuers={[]}
          authorities={[AUTHORITY] as any}
          loadError={null}
          updateQueryAt={jest.fn()}
          updateQuerySubField={jest.fn()}
          setAuthoritiesAt={setAuthoritiesAt}
          updateEntityAt={jest.fn()}
          handleQueryTypeChangeAt={jest.fn()}
        />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByTestId('trust-check-query-0-authority'));
    fireEvent.click(screen.getByText('Agent identity credential issuer (default)'));

    const picks = setAuthoritiesAt.mock.calls[0][1];
    expect(picks[picks.length - 1]).toEqual({ did: '{{ input.agent.identity_issuer_did }}' });
  });
});
