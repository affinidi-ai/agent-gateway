import { trustCheckDefinition } from '../trust-check/definition';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import TrustCheckQueryForm from '../trust-check/TrustCheckQueryForm';
import type { TrustCheckQueryConfig } from '../trust-check/definition';

const AUTHORITY = { id: 'a-1', name: 'Payments Authority', did: 'did:web:auth.example' };

const emptyQuery = {
  id: 'q-1',
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  query: {},
} as TrustCheckQueryConfig;

describe('TrustCheckQueryForm loaded after the Trust Check definition', () => {
  it('still writes no authority_source when the agent identity credential issuer is added', () => {
    expect(trustCheckDefinition.type).toBe('trust-check');
    const replaceQueryAt = jest.fn();
    render(
      <MemoryRouter>
        <TrustCheckQueryForm
          queryConfig={emptyQuery}
          index={0}
          isApMa
          registries={[]}
          issuers={[]}
          authorities={[AUTHORITY] as any}
          loadError={null}
          updateQueryAt={jest.fn()}
          updateQuerySubField={jest.fn()}
          replaceQueryAt={replaceQueryAt}
          updateEntityAt={jest.fn()}
          handleQueryTypeChangeAt={jest.fn()}
        />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority'));
    fireEvent.click(
      screen.getByTestId('trust-check-query-0-add-authority-option-agent-identity-issuer')
    );
    fireEvent.click(screen.getByTestId('trust-check-query-0-add-authority-confirm'));

    const [, next] = replaceQueryAt.mock.calls[0];
    expect(next.query).toEqual({ authority_id: '{{ input.agent.identity_issuer_did }}' });
    expect(next).not.toHaveProperty('authority_source');
  });
});
