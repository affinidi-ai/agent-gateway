import React from 'react';
import type { Identity } from '../../types';
import { formatDateTime } from '../../utils/stringUtils';
import type { FieldChange, IdentityVersion } from './identityVersions';
import { useEntryVersions } from './useEntryVersions';

interface VersionListProps {
  versions: IdentityVersion[];
  /** DID whose versions are marked, for a deep link to an earlier DID. */
  highlightedDid?: string;
  /** Actions of the DID a version introduces; return `null` to show none. */
  renderActions?: (version: IdentityVersion) => React.ReactNode;
}

interface IdentityVersionHistoryProps extends Omit<VersionListProps, 'versions'> {
  /** Every identity of the entry; rotations are fetched for those that have any. */
  members: Identity[];
  /** The entry's primary DID, whose latest version is the current one. */
  currentDid: string;
}

const formatValue = (value: unknown): string =>
  typeof value === 'string' ? value : JSON.stringify(value);

const ChangeLine: React.FC<{ change: FieldChange; first: boolean }> = ({ change, first }) => {
  if (first || !('from' in change)) {
    return (
      <>
        <code>{change.field}</code>
        {first ? ': ' : ' added: '}
        <code className="text-body">{formatValue(change.to)}</code>
      </>
    );
  }
  if (!('to' in change)) {
    return (
      <>
        <code>{change.field}</code> removed (was{' '}
        <code className="text-body">{formatValue(change.from)}</code>)
      </>
    );
  }
  return (
    <>
      <code>{change.field}</code>: <code className="text-body">{formatValue(change.from)}</code> →{' '}
      <code className="text-body">{formatValue(change.to)}</code>
    </>
  );
};

const emptyChangesText = (version: IdentityVersion): string =>
  version.kind === 'rotation'
    ? 'The stored credential was updated, by a new value or an edit to its details; its identity fields did not change.'
    : 'No field changes.';

// A rotation without field changes is an API key update, which may not have changed its value.
const rotationLabel = (version: IdentityVersion): string =>
  version.changes.length > 0 ? 'Credential rotated' : 'Credential updated';

const VersionList: React.FC<VersionListProps> = ({ versions, highlightedDid, renderActions }) => (
  <>
    {versions.length === 0 && (
      <p className="small text-muted mb-2" data-testid="identities-version-history-empty">
        No earlier DIDs or credential rotations recorded.
      </p>
    )}
    <ol className="list-unstyled mb-2">
      {versions.map(version => {
        const first = version.number === 1;
        const highlighted = version.did === highlightedDid;
        return (
          <li
            key={`${version.did}-${version.number}`}
            className={`border rounded px-3 py-2 mb-2${highlighted ? ' border-primary' : ''}`}
            data-testid={`identities-version-${version.number}`}
            data-highlighted={highlighted || undefined}
          >
            <div className="d-flex flex-wrap align-items-center gap-2 small">
              {version.current ? (
                <span className="badge text-bg-success">Current</span>
              ) : (
                <span className="badge text-bg-secondary">v{version.number}</span>
              )}
              <span className="text-muted">
                {version.at ? formatDateTime(version.at, true) : 'Time unknown'}
              </span>
              {renderActions && version.kind === 'did' && (
                <span className="ms-auto">{renderActions(version)}</span>
              )}
            </div>
            <ul
              className="small mt-2 mb-0 ps-3"
              data-testid={`identities-version-${version.number}-changes`}
            >
              <li className="mb-1">
                <code>DID</code>: <code className="text-body text-break">{version.did}</code>
                {version.kind === 'rotation' && (
                  <span className="text-muted ms-1">({rotationLabel(version)})</span>
                )}
              </li>
              {version.changes.map(change => (
                <li key={change.field} className="mb-1 text-break">
                  <ChangeLine change={change} first={first} />
                </li>
              ))}
            </ul>
            {version.changes.length === 0 && (
              <div className="small text-muted">{emptyChangesText(version)}</div>
            )}
          </li>
        );
      })}
    </ol>
  </>
);

/** The entry's versions, loaded when shown: mount it only while Version History is open. */
export const IdentityVersionHistory: React.FC<IdentityVersionHistoryProps> = ({
  members,
  currentDid,
  ...listProps
}) => {
  const state = useEntryVersions(members, currentDid);
  return (
    <div data-testid="identities-version-history" aria-busy={state.status === 'loading'}>
      {state.status === 'loading' && (
        <p
          className="small text-muted mb-2"
          role="status"
          data-testid="identities-version-history-loading"
        >
          <span className="spinner-border spinner-border-sm me-2" aria-hidden="true" />
          Loading version history…
        </p>
      )}
      {state.status === 'error' && (
        <div
          className="alert alert-danger small py-2 mb-2 d-flex flex-wrap align-items-center gap-2"
          role="alert"
          data-testid="identities-version-history-error"
        >
          <span className="text-break">Could not load version history: {state.message}</span>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm ms-auto"
            onClick={state.retry}
            data-testid="identities-version-history-retry-button"
          >
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && <VersionList versions={state.versions} {...listProps} />}
    </div>
  );
};

export default IdentityVersionHistory;
