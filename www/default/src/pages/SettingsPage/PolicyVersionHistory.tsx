import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import { formatDateTime } from '../../utils/stringUtils';

interface PolicyVersion {
  version: number;
  policy: string;
  content_hash: string;
  created_at: string;
  created_by?: string;
  note?: string;
  name?: string;
  description?: string;
}

interface PolicyVersionHistoryProps {
  policyId: string;
  /** Current name / description, used as a fallback for older revisions that
   * predate per-version snapshots. */
  name?: string;
  description?: string;
  /** Bumped by the editor after a save so the list reloads with the new version. */
  refreshKey?: number;
}

const preStyle: React.CSSProperties = {
  fontSize: '0.8rem',
  maxHeight: '320px',
  overflow: 'auto',
  whiteSpace: 'pre-wrap',
};

/** Render Rego with lines absent from `otherLines` tinted, for a simple compare. */
const DiffPre: React.FC<{ policy: string; otherLines: Set<string>; tint: string }> = ({
  policy,
  otherLines,
  tint,
}) => (
  <pre className="p-2 rounded mb-0 policy-preview-block" style={preStyle}>
    {policy.split('\n').map((line, i) => (
      <div
        key={i}
        style={!otherLines.has(line) && line.trim() ? { backgroundColor: tint } : undefined}
      >
        <code>{line || ' '}</code>
      </div>
    ))}
  </pre>
);

/** Shortens a `sha256:<hex>` content hash for a dense table cell; the full value is a tooltip. */
const truncateHash = (hash: string): string => (hash.length > 19 ? `${hash.slice(0, 19)}…` : hash);

/**
 * Immutable version history of a policy definition, newest first. Each revision
 * keeps its own name / description / author snapshot; selecting an older version
 * compares its Rego against the current version (removed lines tinted red, added
 * lines tinted green).
 */
const PolicyVersionHistory: React.FC<PolicyVersionHistoryProps> = ({
  policyId,
  name,
  description,
  refreshKey,
}) => {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const resp = await apiClient.fetch(
          `/api/v1/policy-definitions/${encodeURIComponent(policyId)}/versions`
        );
        if (!resp.ok) throw new Error(`Failed to load versions: ${resp.statusText}`);
        const data = (await resp.json()) as PolicyVersion[];
        if (active) setVersions(data);
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : 'Failed to load versions');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [policyId, refreshKey]);

  const current = versions[0];
  const selectedVersion = useMemo(
    () => versions.find(v => v.version === selected) ?? null,
    [versions, selected]
  );
  const currentLines = useMemo(() => new Set((current?.policy ?? '').split('\n')), [current]);
  const selectedLines = useMemo(
    () => new Set((selectedVersion?.policy ?? '').split('\n')),
    [selectedVersion]
  );

  return (
    <div className="card shadow-sm mb-4" data-testid="policy-version-history">
      <div className="card-body py-3 px-3">
        <h6 className="font-weight-bold text-primary mb-2">
          <i className="fas fa-history me-2"></i>
          Version history
          {!loading && <span className="badge text-bg-secondary ms-2">{versions.length}</span>}
        </h6>
        {loading ? (
          <div className="text-center py-3">
            <div className="spinner-border spinner-border-sm text-primary" role="status" />
          </div>
        ) : error ? (
          <div className="alert alert-danger py-2 px-3 mb-0">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {error}
          </div>
        ) : (
          <>
            <div className="table-responsive">
              <table className="table table-sm mb-0">
                <thead className="thead-light">
                  <tr>
                    <th style={{ width: '80px' }}></th>
                    <th style={{ width: '60px' }}>Version</th>
                    <th>Name</th>
                    <th>SHA</th>
                    <th>Created</th>
                    <th>Author</th>
                    <th>Description</th>
                    <th style={{ width: '70px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {versions.map(v => {
                    const isCurrent = !!current && v.version === current.version;
                    // Older revisions predating snapshots fall back to the live
                    // values only for the current row; frozen rows show a dash.
                    const rowName = v.name ?? (isCurrent ? name : undefined);
                    const rowDesc = v.description ?? (isCurrent ? description : undefined);
                    return (
                      <tr key={v.version} data-testid={`policy-version-${v.version}`}>
                        <td>{isCurrent && <span className="badge text-bg-info">current</span>}</td>
                        <td>v{v.version}</td>
                        <td className="small">{rowName || '—'}</td>
                        <td>
                          <code className="small text-muted" title={v.content_hash}>
                            {truncateHash(v.content_hash)}
                          </code>
                        </td>
                        <td className="small text-muted">{formatDateTime(v.created_at, true)}</td>
                        <td className="small">{v.created_by || '—'}</td>
                        <td className="small text-muted">{rowDesc || '—'}</td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary"
                            onClick={() => setSelected(selected === v.version ? null : v.version)}
                            data-testid={`policy-version-view-${v.version}`}
                          >
                            {selected === v.version ? 'Hide' : 'View'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {selectedVersion && current && selectedVersion.version !== current.version && (
              <div className="row mt-3">
                <div className="col-md-6">
                  <div className="small font-weight-bold text-muted mb-1">
                    v{selectedVersion.version} (removed lines tinted)
                  </div>
                  <DiffPre
                    policy={selectedVersion.policy}
                    otherLines={currentLines}
                    tint="rgba(220,53,69,0.15)"
                  />
                </div>
                <div className="col-md-6">
                  <div className="small font-weight-bold text-muted mb-1">
                    v{current.version} · current (added lines tinted)
                  </div>
                  <DiffPre
                    policy={current.policy}
                    otherLines={selectedLines}
                    tint="rgba(25,135,84,0.15)"
                  />
                </div>
              </div>
            )}
            {selectedVersion && (
              <div className="mt-2 small text-muted d-flex flex-wrap align-items-center">
                <code className="me-2">{selectedVersion.content_hash}</code>
                {selectedVersion.note && <span>· {selectedVersion.note}</span>}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default PolicyVersionHistory;
