import React from 'react';
import type { CredentialPrincipal } from '../../types';
import { CredentialPrincipalLabel } from './IdentityNameCell';
import type { SurfaceLink } from './useIdentityRows';

interface SurfaceLinkButtonProps {
  surface: SurfaceLink;
  onOpen: (surfaceId: string) => void;
  style?: React.CSSProperties;
  'data-testid'?: string;
}

/** One surface: a link to a live surface, or the muted name of a deleted one with a Deleted badge. */
export const SurfaceLinkButton: React.FC<SurfaceLinkButtonProps> = ({
  surface,
  onOpen,
  style,
  'data-testid': testId,
}) => {
  if (surface.deleted) {
    return (
      <span
        className="d-inline-flex align-items-center flex-nowrap"
        data-testid="identities-surface-deleted"
      >
        <span className="text-muted" title={surface.id} style={style}>
          {surface.name}
        </span>
        <span
          className="badge text-bg-secondary ms-1"
          title="This agent surface has been deleted"
          data-testid="identities-surface-deleted-badge"
        >
          Deleted
        </span>
      </span>
    );
  }
  return (
    <button
      type="button"
      onClick={e => {
        e.stopPropagation();
        onOpen(surface.id);
      }}
      className="btn btn-link p-0 align-baseline text-primary"
      style={style}
      data-testid={testId}
    >
      {surface.name}
    </button>
  );
};

interface IdentitySurfaceCellProps {
  links: SurfaceLink[];
  principal?: CredentialPrincipal;
  onOpenSurface: (surfaceId: string) => void;
}

/** Agent Surface cell: every surface (one per line), then the credential principal. */
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
            <SurfaceLinkButton
              surface={link}
              onOpen={onOpenSurface}
              style={{ fontSize: '0.75rem' }}
              data-testid="identities-surface-link"
            />
          </li>
        ))}
      </ul>
    )}
    <CredentialPrincipalLabel principal={principal} />
  </>
);

export default IdentitySurfaceCell;
