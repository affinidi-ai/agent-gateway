import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Badge } from '../../components/shared/Badge';
import { apiClient } from '../../api';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';
import { AppButton } from '../../components/shared/AppButton';
import SearchInput from '../../components/shared/SearchInput';
import { VpJwtRow, parseVp } from '../../components/shared/VpViewer';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';

interface AuditCallerContext {
  auth_method: string;
  iss?: string;
  aud?: string;
  sub?: string;
  email?: string;
  name?: string;
  email_redacted?: string;
  name_redacted?: string;
}

interface AuditEvent {
  timestamp: string;
  /** Unit variants are a plain string; struct variants are a single-key object e.g. { policy_decision: {...} } */
  event: string | Record<string, unknown>;
  agent_did?: string;
  agent_identity_did?: string;
  user_identity_hash?: string;
  provider_id?: string;
  provider_name?: string;
  channel_id?: string;
  channel_name?: string;
  target_endpoint?: string;
  protocol?: string;
  scopes?: string[];
  token_id?: string;
  inject_as?: string;
  via_fabric: boolean;
  caller?: AuditCallerContext;
  mcp_tool_name?: string;
  vp_jwt?: string;
  detail?: string;
}

interface AuditLogPage {
  events: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

interface CredentialAuditTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const PAGE_SIZE = 25;

const eventBadgeMap: Record<string, { color: string; label: string }> = {
  token_injected: { color: 'success', label: 'Injected' },
  token_refreshed: { color: 'info', label: 'Refreshed' },
  consent_granted: { color: 'primary', label: 'Consent Granted' },
  consent_required: { color: 'warning', label: 'Consent Required' },
  refresh_failed: { color: 'danger', label: 'Refresh Failed' },
  token_revoked: { color: 'danger', label: 'Revoked' },
  user_tokens_revoked: { color: 'danger', label: 'User Revoked' },
  token_not_found: { color: 'secondary', label: 'Not Found' },
  vp_injected: { color: 'info', label: 'VP Injected' },
  policy_decision: { color: 'primary', label: 'Policy Decision' },
  trust_check: { color: 'info', label: 'Trust Check' },
};

/** Extract the event name from either a plain string or a struct-variant object. */
function eventName(event: string | Record<string, unknown>): string {
  if (typeof event === 'string') return event;
  if (typeof event === 'object' && event !== null) return Object.keys(event)[0] ?? 'unknown';
  return 'unknown';
}

interface WorkloadIntent {
  protocol?: string;
  method?: string;
  tool?: string;
  resourceUri?: string;
  promptName?: string;
}

function extractIntent(evt: AuditEvent): WorkloadIntent | null {
  if (!evt.vp_jwt) return null;
  const { parsed } = parseVp(evt.vp_jwt);
  if (!parsed || typeof parsed !== 'object') return null;
  const root = parsed as Record<string, unknown>;
  const vcCandidate = root.verifiableCredential ?? root.vp ?? root;
  const vc = Array.isArray(vcCandidate)
    ? (vcCandidate[0] as Record<string, unknown>)
    : (vcCandidate as Record<string, unknown>);
  if (!vc || typeof vc !== 'object') return null;
  const subject = (vc as Record<string, unknown>).credentialSubject as
    | Record<string, unknown>
    | undefined;
  if (!subject) return null;
  const subj = Array.isArray(subject) ? (subject[0] as Record<string, unknown>) : subject;
  const wb = subj?.workloadBinding as Record<string, unknown> | undefined;
  const intent = wb?.intent as WorkloadIntent | undefined;
  return intent ?? null;
}

const CredentialAuditTab: React.FC<CredentialAuditTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const [data, setData] = useState<AuditLogPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [eventFilter, setEventFilter] = useState<string>('');

  const loadAudit = async (p: number, filter?: string) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ page: String(p), page_size: String(PAGE_SIZE) });
      if (filter) params.set('filter', filter);
      const resp = await apiClient.fetch(`/api/v1/delegation-audit?${params}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json: AuditLogPage = await resp.json();
      setData(json);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudit(page, searchTerm || undefined);
  }, [page, searchTerm]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const filteredEvents = useMemo(() => {
    if (!data) return [];
    if (!eventFilter) return data.events;
    return data.events.filter(e => eventName(e.event) === eventFilter);
  }, [data, eventFilter]);

  useEffect(() => {
    onFilteredCountChange?.(filteredEvents.length);
  }, [filteredEvents.length, onFilteredCountChange]);

  const eventTypes = useMemo(() => {
    if (!data) return [];
    const types = new Set(data.events.map(e => eventName(e.event)));
    return Array.from(types).sort();
  }, [data]);

  const truncate = (s: string, len: number) => (s.length > len ? s.substring(0, len) + '…' : s);

  const handlePageChange = (p: number) => {
    setPage(p);
    setExpandedIdx(null);
  };

  const renderBadge = (event: string) => {
    const badge = eventBadgeMap[event] || { color: 'secondary', label: event.replace(/_/g, ' ') };
    return <span className={`badge text-bg-${badge.color}`}>{badge.label}</span>;
  };

  /**
   * Render a compact badge describing what the caller was actually trying to
   * do, sourced from the signed VP's `workloadBinding.intent`. Falls back to
   * `mcp_tool_name` (the dedicated audit column) when the VP is absent so
   * pre-VP rows still surface useful context.
   *
   * Shape: `protocol → method[:tool]` (e.g. `mcp → tools/call:get_weather`).
   * For non-MCP protocols where intent isn't populated yet we render nothing
   * — the protocol badge in the surface column already covers that case.
   */
  const renderIntent = (evt: AuditEvent) => {
    const intent = extractIntent(evt);
    const protocol = intent?.protocol ?? evt.protocol;
    const method = intent?.method;
    const tool = intent?.tool ?? evt.mcp_tool_name;

    if (!method && !tool) return <span className="text-muted">—</span>;

    const label = [method, tool].filter(Boolean).join(':');
    return (
      <span
        className="badge text-bg-dark"
        title={protocol ? `${protocol} → ${label}` : label}
        style={{ fontFamily: 'var(--bs-font-monospace)', fontSize: '0.7rem' }}
      >
        {label}
      </span>
    );
  };

  const renderCaller = (caller?: AuditCallerContext) => {
    if (!caller) return <span className="text-muted">—</span>;
    const email = caller.email ?? caller.email_redacted;
    const name = caller.name ?? caller.name_redacted;
    return (
      <div style={{ fontSize: '0.82rem' }}>
        <span className="badge text-bg-secondary me-1">{caller.auth_method}</span>
        {email && (
          <span className="text-muted ms-1" title="Caller email">
            <i className="fas fa-envelope fa-xs me-1" />
            {email}
          </span>
        )}
        {name && (
          <span className="text-muted ms-2" title="Caller name">
            <i className="fas fa-user fa-xs me-1" />
            {name}
          </span>
        )}
      </div>
    );
  };

  const renderExpandedRow = (evt: AuditEvent) => (
    <tr className="expanded-detail-row">
      <td colSpan={7} className="p-0">
        <div className="px-4 py-3" style={{ borderTop: 'none' }}>
          <div className="row g-3">
            <div className="col-md-6">
              <table
                className="table table-sm table-borderless mb-0"
                style={{ fontSize: '0.85rem' }}
              >
                <tbody>
                  <tr>
                    <td className="text-muted fw-semibold" style={{ width: '140px' }}>
                      Timestamp
                    </td>
                    <td>
                      <code>{formatDateTime(evt.timestamp, true)}</code>
                    </td>
                  </tr>
                  {evt.caller && (
                    <>
                      <tr>
                        <td className="text-muted fw-semibold" style={{ width: '140px' }}>
                          Auth Method
                        </td>
                        <td>
                          <code>{evt.caller.auth_method}</code>
                        </td>
                      </tr>
                      {evt.caller.iss && (
                        <tr>
                          <td className="text-muted fw-semibold">Issuer</td>
                          <td>
                            <code>{evt.caller.iss}</code>
                          </td>
                        </tr>
                      )}
                      {evt.caller.aud && (
                        <tr>
                          <td className="text-muted fw-semibold">Audience</td>
                          <td>
                            <code>{evt.caller.aud}</code>
                          </td>
                        </tr>
                      )}
                      {evt.caller.sub && (
                        <tr>
                          <td className="text-muted fw-semibold">Subject</td>
                          <td>
                            <code>{evt.caller.sub}</code>
                          </td>
                        </tr>
                      )}
                      {(evt.caller.email ?? evt.caller.email_redacted) && (
                        <tr>
                          <td className="text-muted fw-semibold">Email</td>
                          <td>{evt.caller.email ?? evt.caller.email_redacted}</td>
                        </tr>
                      )}
                      {(evt.caller.name ?? evt.caller.name_redacted) && (
                        <tr>
                          <td className="text-muted fw-semibold">Name</td>
                          <td>{evt.caller.name ?? evt.caller.name_redacted}</td>
                        </tr>
                      )}
                    </>
                  )}
                  {(evt.channel_name || evt.channel_id) && (
                    <tr>
                      <td className="text-muted fw-semibold" style={{ width: '140px' }}>
                        Agent Surface
                      </td>
                      <td>
                        {evt.channel_id ? (
                          <Link to={`/surfaces/${encodeURIComponent(evt.channel_id)}`}>
                            {evt.channel_name || evt.channel_id}
                          </Link>
                        ) : (
                          evt.channel_name
                        )}
                      </td>
                    </tr>
                  )}
                  {evt.target_endpoint && (
                    <tr>
                      <td className="text-muted fw-semibold">Target</td>
                      <td>
                        <code>{evt.target_endpoint}</code>
                      </td>
                    </tr>
                  )}
                  {evt.protocol && (
                    <tr>
                      <td className="text-muted fw-semibold">Protocol</td>
                      <td>
                        <span className="badge text-bg-info">{evt.protocol}</span>
                      </td>
                    </tr>
                  )}
                  {evt.inject_as && (
                    <tr>
                      <td className="text-muted fw-semibold">Inject As</td>
                      <td>
                        <code>{evt.inject_as}</code>
                      </td>
                    </tr>
                  )}
                  {evt.mcp_tool_name && (
                    <tr>
                      <td className="text-muted fw-semibold">MCP Tool</td>
                      <td>
                        <code>{evt.mcp_tool_name}</code>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="col-md-6">
              <table
                className="table table-sm table-borderless mb-0"
                style={{ fontSize: '0.85rem' }}
              >
                <tbody>
                  {evt.agent_did && (
                    <tr>
                      <td className="text-muted fw-semibold" style={{ width: '140px' }}>
                        Agent DID
                      </td>
                      <td>
                        <code style={{ wordBreak: 'break-all' }}>{evt.agent_did}</code>
                      </td>
                    </tr>
                  )}
                  {evt.agent_identity_did && evt.agent_identity_did !== evt.agent_did && (
                    <tr>
                      <td className="text-muted fw-semibold" style={{ width: '140px' }}>
                        Agent Identity
                      </td>
                      <td>
                        <code style={{ wordBreak: 'break-all' }}>{evt.agent_identity_did}</code>
                      </td>
                    </tr>
                  )}
                  {evt.user_identity_hash && (
                    <tr>
                      <td className="text-muted fw-semibold">User Hash</td>
                      <td>
                        <code style={{ wordBreak: 'break-all' }}>{evt.user_identity_hash}</code>
                      </td>
                    </tr>
                  )}
                  {(evt.provider_name || evt.provider_id) && (
                    <tr>
                      <td className="text-muted fw-semibold">Provider</td>
                      <td>
                        {evt.provider_id ? (
                          <Link to={`/credential-providers/${encodeURIComponent(evt.provider_id)}`}>
                            <strong>{evt.provider_name || evt.provider_id}</strong>
                          </Link>
                        ) : (
                          <strong>{evt.provider_name}</strong>
                        )}
                      </td>
                    </tr>
                  )}
                  {evt.token_id && (
                    <tr>
                      <td className="text-muted fw-semibold">Token ID</td>
                      <td>
                        <code>{evt.token_id}</code>
                      </td>
                    </tr>
                  )}
                  {evt.scopes && evt.scopes.length > 0 && (
                    <tr>
                      <td className="text-muted fw-semibold">Scopes</td>
                      <td>
                        {evt.scopes.map((s, i) => (
                          <span key={i} className="badge text-bg-secondary me-1">
                            {s}
                          </span>
                        ))}
                      </td>
                    </tr>
                  )}
                  <tr>
                    <td className="text-muted fw-semibold">Via Fabric</td>
                    <td>
                      {evt.via_fabric ? (
                        <span className="badge text-bg-info">G2G</span>
                      ) : (
                        <span className="badge text-bg-secondary">No</span>
                      )}
                    </td>
                  </tr>
                  {evt.detail && (
                    <tr>
                      <td className="text-muted fw-semibold">Detail</td>
                      <td>{evt.detail}</td>
                    </tr>
                  )}
                  {evt.vp_jwt ? (
                    <VpJwtRow vpJwt={evt.vp_jwt} />
                  ) : (
                    <tr>
                      <td
                        className="text-muted fw-semibold"
                        style={{ width: '140px', whiteSpace: 'nowrap' }}
                      >
                        Verifiable Presentation
                      </td>
                      <td>
                        <span className="text-muted">Not presented</span>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </td>
    </tr>
  );

  const totalPages = data ? data.total_pages : 1;

  const PaginationControls: React.FC = () => {
    if (totalPages <= 1) return null;
    const pages = Array.from({ length: totalPages }, (_, i) => i + 1)
      .filter(p => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
      .reduce<(number | '...')[]>((acc, p, idx, arr) => {
        if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('...');
        acc.push(p);
        return acc;
      }, []);

    return (
      <div className="d-flex justify-content-between align-items-center mt-2 px-1">
        <small className="text-muted">
          {data
            ? `${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, data.total)} of ${data.total}`
            : ''}
        </small>
        <nav>
          <ul className="pagination pagination-sm mb-0">
            <li className={`page-item ${page <= 1 ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => handlePageChange(page - 1)}>
                &lsaquo;
              </button>
            </li>
            {pages.map((p, idx) =>
              p === '...' ? (
                <li key={`ellipsis-${idx}`} className="page-item disabled">
                  <span className="page-link">…</span>
                </li>
              ) : (
                <li key={p} className={`page-item ${p === page ? 'active' : ''}`}>
                  <button className="page-link" onClick={() => handlePageChange(p as number)}>
                    {p}
                  </button>
                </li>
              )
            )}
            <li className={`page-item ${page >= totalPages ? 'disabled' : ''}`}>
              <button className="page-link" onClick={() => handlePageChange(page + 1)}>
                &rsaquo;
              </button>
            </li>
          </ul>
        </nav>
      </div>
    );
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-clipboard-list me-1" /> Credential Delegation Audit Log
          {data && (
            <Badge value={data.total} className="ms-2" ariaLabel={`${data.total} audit events`} />
          )}
        </h6>
        <div className="d-flex align-items-center gap-2">
          {!externalProvided && (
            <SearchInput
              value={internalSearchTerm}
              onChange={v => {
                setInternalSearchTerm(v);
                setPage(1);
              }}
              placeholder="Filter audit events..."
            />
          )}
          {eventTypes.length > 1 && (
            <select
              className="form-select form-select-sm"
              style={{ width: '180px' }}
              value={eventFilter}
              onChange={e => setEventFilter(e.target.value)}
            >
              <option value="">All Events</option>
              {eventTypes.map(t => (
                <option key={t} value={t}>
                  {eventBadgeMap[t]?.label || t} (
                  {data?.events.filter(e => eventName(e.event) === t).length})
                </option>
              ))}
            </select>
          )}
          <AppButton
            variant="primary"
            size="md"
            className="shadow-sm"
            onClick={() => loadAudit(page, searchTerm || undefined)}
            iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
          >
            Refresh
          </AppButton>
        </div>
      </div>
      <div className="card-body">
        <div className="alert alert-info d-flex align-items-start mb-3" role="note">
          <i className="fas fa-info-circle mt-1 me-2" />
          <div className="small">
            This tamper-evident log records credential-delegation events - consent granted/required,
            downstream tokens issued, refreshed or revoked, and Verifiable Presentations injected
            into proxied requests on behalf of the calling agent. Entries appear only when a request
            actually exercises the delegation pipeline, such as when a token is injected or
            refreshed.
          </div>
        </div>
        {loading && !data ? (
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              minHeight: '200px',
            }}
          >
            <div className="spinner-border text-primary" role="status" />
          </div>
        ) : error ? (
          <div className="alert alert-danger">
            <i className="fas fa-exclamation-triangle me-1" /> Failed to load audit log: {error}
          </div>
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            icon="fa-clipboard-list"
            title="No credential audit events yet"
            body="Credential audit events record every credential the gateway issues, verifies, or delegates. They appear here as activity occurs."
            docsHref={DOCS_URL.credentials}
          />
        ) : (
          <>
            <div className="table-responsive">
              <table className="table table-sm table-hover">
                <thead>
                  <tr>
                    <th style={{ width: '160px' }}>Time</th>
                    <th style={{ width: '130px' }}>Event</th>
                    <th style={{ width: '180px' }}>Intent</th>
                    <th>Caller Context</th>
                    <th>Downstream Provider</th>
                    <th>Agent Surface</th>
                    <th style={{ width: '50px' }} />
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((evt, idx) => (
                    <React.Fragment key={`${evt.timestamp}-${idx}`}>
                      <tr
                        onClick={() => setExpandedIdx(expandedIdx === idx ? null : idx)}
                        style={{ cursor: 'pointer' }}
                        className={expandedIdx === idx ? 'table-active' : ''}
                      >
                        <td title={formatDateTime(evt.timestamp, true)}>
                          <small>{timeAgo(evt.timestamp)}</small>
                        </td>
                        <td>{renderBadge(eventName(evt.event))}</td>
                        <td>{renderIntent(evt)}</td>
                        <td>{renderCaller(evt.caller)}</td>
                        <td>
                          {evt.provider_id ? (
                            <Link
                              to={`/credential-providers/${encodeURIComponent(evt.provider_id)}`}
                              onClick={e => e.stopPropagation()}
                              title={evt.provider_id}
                            >
                              {evt.provider_name || evt.provider_id}
                            </Link>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td>
                          {evt.channel_id ? (
                            <Link
                              to={`/surfaces/${encodeURIComponent(evt.channel_id)}`}
                              onClick={e => e.stopPropagation()}
                              title={evt.channel_id}
                            >
                              {evt.channel_name || truncate(evt.channel_id, 12)}
                            </Link>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                          {evt.protocol && (
                            <span
                              className="badge text-bg-info ms-1"
                              style={{ fontSize: '0.65rem' }}
                            >
                              {evt.protocol}
                            </span>
                          )}
                        </td>
                        <td className="text-center">
                          <i
                            className={`fas fa-chevron-${expandedIdx === idx ? 'up' : 'down'} text-muted`}
                          />
                        </td>
                      </tr>
                      {expandedIdx === idx && renderExpandedRow(evt)}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationControls />
          </>
        )}
      </div>
    </div>
  );
};

export default CredentialAuditTab;
