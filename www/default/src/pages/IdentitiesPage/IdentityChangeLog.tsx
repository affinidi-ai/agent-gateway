import React from 'react';
import { Badge } from '../../components/shared/Badge';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import type { GroupableIdentity, IdentityChange, IdentityChangeKind } from './identityGrouping';

const KIND_LABELS: Record<IdentityChangeKind, string> = {
  did: 'DID',
  credential: 'Credential',
  claims: 'Claims',
};

const credentialLabel = (identity: GroupableIdentity): string =>
  identity.credential_principal?.name ||
  identity.credential_principal?.id ||
  (identity.identity_hash ? topAndTail(identity.identity_hash, 8, 4) : '—');

const Transition: React.FC<{ label: string; from: React.ReactNode; to: React.ReactNode }> = ({
  label,
  from,
  to,
}) => (
  <div className="small">
    <span className="text-muted me-1">{label}:</span>
    {from}
    <i className="fas fa-arrow-right mx-1 text-muted" aria-label="changed to"></i>
    {to}
  </div>
);

const ShortDid: React.FC<{ did: string }> = ({ did }) => (
  <code style={{ fontSize: '0.75rem' }} title={did}>
    {topAndTail(did, 20, 12)}
  </code>
);

interface IdentityChangeLogProps<T extends GroupableIdentity> {
  changes: IdentityChange<T>[];
}

export function IdentityChangeLog<T extends GroupableIdentity>({
  changes,
}: IdentityChangeLogProps<T>) {
  if (changes.length === 0) {
    return <p className="text-muted small mb-0">No identity changes recorded for this surface.</p>;
  }

  return (
    <ol className="list-unstyled mb-0" data-testid="identities-change-log">
      {[...changes].reverse().map(change => (
        <li
          key={`${change.previous.did}->${change.current.did}@${change.at ?? ''}`}
          className="border-bottom py-2"
          data-testid="identities-change-log-entry"
        >
          <div className="d-flex align-items-center flex-wrap gap-1 mb-1">
            <small className="text-muted me-2">
              {change.at ? formatDateTime(change.at, true) : 'Unknown time'}
            </small>
            {change.kinds.map(kind => (
              <Badge key={kind} tone="secondary" size="sm" value={KIND_LABELS[kind]} />
            ))}
          </div>
          {change.kinds.includes('did') && (
            <Transition
              label="DID"
              from={<ShortDid did={change.previous.did} />}
              to={<ShortDid did={change.current.did} />}
            />
          )}
          {change.kinds.includes('credential') && (
            <Transition
              label="Credential"
              from={<span>{credentialLabel(change.previous)}</span>}
              to={<span>{credentialLabel(change.current)}</span>}
            />
          )}
          {change.kinds.includes('claims') && (
            <div className="small">
              <span className="text-muted me-1">Claims changed:</span>
              {change.changedClaims.join(', ')}
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}

interface IdentityChangeLogSectionProps<
  T extends GroupableIdentity,
> extends IdentityChangeLogProps<T> {
  expanded: boolean;
  onToggle: () => void;
}

export function IdentityChangeLogSection<T extends GroupableIdentity>({
  changes,
  expanded,
  onToggle,
}: IdentityChangeLogSectionProps<T>) {
  return (
    <div className="card mb-2">
      <div
        className="card-header py-1 bg-light"
        style={{ cursor: 'pointer' }}
        onClick={onToggle}
        data-testid="identities-change-log-toggle"
      >
        <small className="mb-0 text-muted">
          <i className={`fas fa-chevron-${expanded ? 'down' : 'right'} me-2`}></i>
          <i className="fas fa-history"></i> Change Log
          <Badge
            value={changes.length}
            size="sm"
            tone="secondary"
            className="ms-2"
            ariaLabel={`${changes.length} identity changes`}
          />
        </small>
      </div>
      {expanded && (
        <div className="card-body py-2 px-3">
          <IdentityChangeLog changes={changes} />
        </div>
      )}
    </div>
  );
}

export default IdentityChangeLog;
