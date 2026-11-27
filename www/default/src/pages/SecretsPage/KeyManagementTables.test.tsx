import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SurfaceMappingTable } from './KeyManagementTables';
import type { SurfaceMapping } from './keyManagementTypes';

const mapping = (overrides: Partial<SurfaceMapping> = {}): SurfaceMapping => ({
  surface_id: 's1',
  surface_name: 'Support surface',
  backend: 'inherit',
  inherits: true,
  derived_context: 'ctx:_global/s1',
  ...overrides,
});

describe('SurfaceMappingTable', () => {
  it('shows a surface that sets nothing as inheriting', () => {
    render(<SurfaceMappingTable mappings={[mapping()]} />);

    expect(screen.getByText('inherit')).toBeInTheDocument();
    expect(screen.queryByTestId('key-mapping-via-issuer-s1')).not.toBeInTheDocument();
  });

  it("shows the issuer's backend and says the surface follows it", () => {
    render(
      <SurfaceMappingTable
        mappings={[
          mapping({
            backend: 'vta',
            connection_id: 'agent-1',
            context_id: 'ctx-issuer',
            key_id: 'key-issuer',
            via_issuer: 'Research',
          }),
        ]}
      />
    );

    expect(screen.getByTestId('key-mapping-via-issuer-s1')).toHaveTextContent(
      'via issuer Research'
    );
    expect(screen.getByText('vta')).toBeInTheDocument();
    expect(screen.getByText('ctx-issuer')).toBeInTheDocument();
    expect(screen.queryByText('inherit')).not.toBeInTheDocument();
  });

  it("shows a surface's own choice without an issuer note", () => {
    render(<SurfaceMappingTable mappings={[mapping({ backend: 'local', inherits: false })]} />);

    expect(screen.getByText('local')).toBeInTheDocument();
    expect(screen.queryByTestId('key-mapping-via-issuer-s1')).not.toBeInTheDocument();
  });
});
