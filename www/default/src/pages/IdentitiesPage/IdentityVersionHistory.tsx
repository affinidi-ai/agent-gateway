import React from 'react';
import { formatDateTime } from '../../utils/stringUtils';
import type { FieldChange, IdentityVersion } from './identityVersions';

interface IdentityVersionHistoryProps {
  versions: IdentityVersion[];
  /** DID whose versions are marked, for a deep link to an earlier DID. */
  highlightedDid?: string;
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
    ? "The credential's value changed; its identity fields did not."
    : 'No field changes.';

export const IdentityVersionHistory: React.FC<IdentityVersionHistoryProps> = ({
  versions,
  highlightedDid,
}) => (
  <div data-testid="identities-version-history">
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
            className={`border rounded px-2 py-1 mb-2${highlighted ? ' border-primary' : ''}`}
            data-testid={`identities-version-${version.number}`}
            data-highlighted={highlighted || undefined}
          >
            <div className="d-flex flex-wrap align-items-center gap-2 small">
              <span className="badge text-bg-secondary">v{version.number}</span>
              <strong>{version.kind === 'did' ? 'DID' : 'Credential rotated'}</strong>
              {version.current && <span className="badge text-bg-success">Current</span>}
              <span className="text-muted">
                {version.at ? formatDateTime(version.at, true) : 'Time unknown'}
              </span>
              <code className="text-truncate" style={{ maxWidth: '28rem' }} title={version.did}>
                {version.did}
              </code>
            </div>
            {version.changes.length === 0 ? (
              <div className="small text-muted">{emptyChangesText(version)}</div>
            ) : (
              <ul
                className="small mb-0 ps-3"
                data-testid={`identities-version-${version.number}-changes`}
              >
                {version.changes.map(change => (
                  <li key={change.field}>
                    <ChangeLine change={change} first={first} />
                  </li>
                ))}
              </ul>
            )}
          </li>
        );
      })}
    </ol>
    <p className="small text-muted mb-0">
      Certificate and API key rotations are listed from the first use after the gateway began
      recording them; a change found then shows as “Time unknown”.
    </p>
  </div>
);

export default IdentityVersionHistory;
