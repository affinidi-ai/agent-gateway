import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { IdentitySurfaceCell, SurfaceLinkButton } from '../IdentitySurfaceCell';

describe('SurfaceLinkButton', () => {
  it('links a live surface', () => {
    const onOpen = jest.fn();
    render(
      <SurfaceLinkButton
        surface={{ id: 'oxygen', name: 'OXYGEN', archived: false }}
        onOpen={onOpen}
        data-testid="identities-surface-link"
      />
    );

    const link = screen.getByTestId('identities-surface-link');
    expect(link.tagName).toBe('BUTTON');
    expect(link).toHaveTextContent('OXYGEN');
    fireEvent.click(link);
    expect(onOpen).toHaveBeenCalledWith('oxygen');
    expect(screen.queryByTestId('identities-surface-deleted-badge')).not.toBeInTheDocument();
  });

  it('shows the surface of an archived identity by name as plain text marked Deleted', () => {
    render(
      <SurfaceLinkButton
        surface={{ id: 'oxygen', name: 'OXYGEN', archived: true }}
        onOpen={jest.fn()}
        data-testid="identities-surface-link"
      />
    );

    expect(screen.getByTestId('identities-surface-archived')).toHaveTextContent('OXYGEN');
    expect(screen.getByTestId('identities-surface-deleted-badge')).toHaveTextContent('Deleted');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identities-surface-link')).not.toBeInTheDocument();
  });

  it('shows the surface of an archived identity without a known name by its id', () => {
    render(
      <SurfaceLinkButton
        surface={{ id: 'surface-1', name: 'surface-1', archived: true }}
        onOpen={jest.fn()}
      />
    );

    expect(screen.getByTestId('identities-surface-archived')).toHaveTextContent('surface-1');
    expect(screen.getByTestId('identities-surface-deleted-badge')).toHaveTextContent('Deleted');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});

describe('IdentitySurfaceCell', () => {
  it('lists a live surface as a link and a deleted one as plain text marked Deleted', () => {
    render(
      <IdentitySurfaceCell
        links={[
          { id: 'oxygen', name: 'OXYGEN', archived: false },
          { id: 'gone', name: 'GONE', archived: true },
        ]}
        onOpenSurface={jest.fn()}
      />
    );

    expect(screen.getByTestId('identities-surface-link')).toHaveTextContent('OXYGEN');
    expect(screen.getByTestId('identities-surface-archived')).toHaveTextContent('GONE');
    expect(screen.getAllByRole('button')).toHaveLength(1);
  });
});
