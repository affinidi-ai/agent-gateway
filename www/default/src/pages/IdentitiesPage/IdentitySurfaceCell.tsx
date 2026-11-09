import React from 'react';
import type { CredentialPrincipal } from '../../types';
import { CredentialPrincipalLabel } from './IdentityNameCell';
import type { SurfaceLink } from './useIdentityRows';

interface IdentitySurfaceCellProps {
  links: SurfaceLink[];
  principal?: CredentialPrincipal;
  onOpenSurface: (surfaceId: string) => void;
}

/** Agent Surface cell: every surface link (one per line), then the credential principal. */
export const IdentitySurfaceCell: React.FC<IdentitySurfaceCellProps> = ({
  links,
  principal,
  onOpenSurface,
}) => (
  <>
    {links.length === 0 ? (
      <span className="text-muted">-</span>
    ) : (
      <ul className="list-unstyled mb-0" data-testid="identities-surface-list">
        {links.map(link => (
          <li key={link.id}>
            <button
              type="button"
              onClick={e => {
                e.stopPropagation();
                onOpenSurface(link.id);
              }}
              className="btn btn-link p-0 align-baseline text-primary"
              style={{ fontSize: '0.75rem' }}
              data-testid="identities-surface-link"
            >
              {link.name}
            </button>
          </li>
        ))}
      </ul>
    )}
    <CredentialPrincipalLabel principal={principal} />
  </>
);

export default IdentitySurfaceCell;
