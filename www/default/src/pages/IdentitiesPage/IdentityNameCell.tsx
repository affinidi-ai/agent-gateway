import React from 'react';
import { CopyButton } from '../../components/shared/CopyButton';
import { topAndTail } from '../../utils/stringUtils';
import type { CredentialPrincipal, Identity } from '../../types';
import { isSharedManagedDid, surfaceCountLabel } from './sharedManagedDid';

export type NamedIdentity = Pick<
  Identity,
  | 'did'
  | 'display_name'
  | 'display_name_source'
  | 'display_name_verified'
  | 'display_name_pending'
  | 'managed_surfaces'
>;

interface IdentityNameCellProps {
  identity: NamedIdentity;
  liveSurfaceName?: string;
  showName?: boolean;
}

export const parseAgentName = (name: string): { host: string; local: string } | null => {
  const separator = name.indexOf('/@');
  if (separator <= 0 || separator + 2 >= name.length) return null;
  return { host: name.slice(0, separator), local: name.slice(separator + 2) };
};

const AgentName: React.FC<{ name: string; verified: boolean }> = ({ name, verified }) => {
  const parsed = parseAgentName(name);
  return (
    <span title={name}>
      {parsed ? (
        <>
          <span className="text-muted">{parsed.local}</span>
          <span className="text-muted" aria-hidden="true">
            {' · '}
          </span>
          <strong>{parsed.host}</strong>
        </>
      ) : (
        <strong>{name}</strong>
      )}
      {verified && (
        <i
          className="fas fa-check-circle text-success ms-1"
          role="img"
          aria-label="Verified agent name"
          title="Verified agent name"
          data-testid="identities-name-verified"
        ></i>
      )}
    </span>
  );
};

const NameLine: React.FC<{
  identity: NamedIdentity;
  displayName: string;
  liveSurfaceName?: string;
}> = ({ identity, displayName, liveSurfaceName }) => {
  const source = identity.display_name_source;

  if (source === 'agent_name') {
    return <AgentName name={displayName} verified={identity.display_name_verified === true} />;
  }

  return (
    <span>
      <strong>{(source === 'surface_name' && liveSurfaceName) || displayName}</strong>
    </span>
  );
};

export const IdentityNameCell: React.FC<IdentityNameCellProps> = ({
  identity,
  liveSurfaceName,
  showName = true,
}) => {
  const shared = showName && isSharedManagedDid(identity);
  const displayName = showName && !shared ? identity.display_name : undefined;
  const pending = showName && !shared && !displayName && identity.display_name_pending === true;
  const didIsPrimary = !shared && !displayName && !pending;

  return (
    <div className="d-inline-flex flex-column">
      {shared && (
        <>
          <span
            className="text-muted fst-italic"
            title="This DID is the managed agent on more than one surface, so no single name is shown"
            data-testid="identities-unnamed-agent"
          >
            Unnamed Agent
          </span>
          <small className="text-muted" data-testid="identities-shared-surface-count">
            {surfaceCountLabel(identity.managed_surfaces?.length ?? 0)}
          </small>
        </>
      )}
      {displayName && (
        <div className="d-flex align-items-center" data-testid="identities-name">
          <NameLine
            identity={identity}
            displayName={displayName}
            liveSurfaceName={liveSurfaceName}
          />
        </div>
      )}
      {pending && (
        <small
          className="text-muted fst-italic"
          title="Looking up this caller's name"
          data-testid="identities-name-pending"
        >
          resolving…
        </small>
      )}
      <div className="d-inline-flex align-items-center flex-nowrap">
        <code
          style={{ fontSize: didIsPrimary ? undefined : '0.75rem', whiteSpace: 'nowrap' }}
          title={identity.did}
        >
          {topAndTail(identity.did, 20, 16)}
        </code>
        <CopyButton text={identity.did} title="Copy DID" data-testid="identities-copy-did-button" />
      </div>
    </div>
  );
};

export const CredentialPrincipalLabel: React.FC<{ principal?: CredentialPrincipal }> = ({
  principal,
}) => {
  if (!principal) return null;
  const kindLabel = principal.kind === 'certificate' ? 'Certificate' : 'API key';
  return (
    <small
      className="text-muted d-block"
      title={`${kindLabel} ${principal.id}`}
      data-testid="identities-credential-principal"
    >
      <i
        className={`fas ${principal.kind === 'certificate' ? 'fa-certificate' : 'fa-key'} me-1`}
        aria-hidden="true"
      ></i>
      <span className="visually-hidden">{kindLabel}: </span>
      {principal.name || principal.id}
    </small>
  );
};

export default IdentityNameCell;
