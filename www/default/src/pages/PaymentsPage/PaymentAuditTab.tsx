import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { EmptyState } from '../../components/shared/EmptyState';
import { formatDateTime } from '../../utils/stringUtils';
import { PAYMENT_AUDIT_STAGES, type PaymentAuditStage } from '../../types';
import { usePaymentAudit } from './usePaymentAudit';

const STAGE_TONE: Partial<Record<PaymentAuditStage, 'success' | 'info' | 'warning' | 'danger'>> = {
  verified: 'success',
  settled: 'success',
  challenge_issued: 'info',
  authorized: 'info',
  held: 'warning',
  unconfirmed: 'warning',
  failed: 'danger',
  settlement_failed: 'danger',
};

const stageLabel = (stage: string) => stage.replace(/_/g, ' ');

/** `datetime-local` input value to RFC 3339, or nothing when empty or unreadable. */
const toRfc3339 = (local: string): string | undefined => {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};

interface Props {
  surfaceId?: string;
  traceId: string;
  onTraceIdChange: (traceId: string) => void;
}

const PaymentAuditTab: React.FC<Props> = ({ surfaceId, traceId, onTraceIdChange }) => {
  const [stage, setStage] = useState<PaymentAuditStage | ''>('');
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const [pageNumber, setPageNumber] = useState(1);
  const { page, loading, error, refresh } = usePaymentAudit({
    surface_id: surfaceId,
    stage: stage || undefined,
    trace_id: traceId || undefined,
    since: toRfc3339(since),
    until: toRfc3339(until),
    page: pageNumber,
  });

  const reset =
    <T,>(set: (value: T) => void) =>
    (value: T) => {
      set(value);
      setPageNumber(1);
    };

  return (
    <div className="card shadow mb-4" data-testid="payments-audit-tab-panel">
      <div className="card-header py-3 d-flex align-items-center justify-content-between">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-clipboard-list me-2" aria-hidden="true" />
          Payment audit trail
          <Badge value={page.total} className="ms-2" ariaLabel={`${page.total} audit events`} />
        </h6>
        <AppButton
          variant="secondary"
          size="sm"
          onClick={refresh}
          loading={loading}
          loadingLabel="Refreshing..."
          disabled={loading}
          data-testid="payments-audit-refresh-button"
        >
          Refresh
        </AppButton>
      </div>
      <div className="card-body">
        <p className="small text-muted">
          Every <code>payment</code> record the VP Audit Log keeps, newest first. Records are kept
          only while the log selects the <code>payment</code> event (Settings, Audit).
        </p>
        <div className="d-flex flex-wrap gap-2 mb-3">
          <select
            className="form-select form-select-sm"
            style={{ width: 'auto' }}
            aria-label="Stage"
            value={stage}
            onChange={e => reset(setStage)(e.target.value as PaymentAuditStage | '')}
            data-testid="payments-audit-stage-filter"
          >
            <option value="">All stages</option>
            {PAYMENT_AUDIT_STAGES.map(s => (
              <option key={s} value={s}>
                {stageLabel(s)}
              </option>
            ))}
          </select>
          <input
            className="form-control form-control-sm"
            style={{ width: '16rem' }}
            placeholder="Trace id"
            aria-label="Trace id"
            value={traceId}
            onChange={e => {
              onTraceIdChange(e.target.value.trim());
              setPageNumber(1);
            }}
            data-testid="payments-audit-trace-input"
          />
          <input
            type="datetime-local"
            className="form-control form-control-sm"
            style={{ width: 'auto' }}
            aria-label="From"
            value={since}
            onChange={e => reset(setSince)(e.target.value)}
            data-testid="payments-audit-since-input"
          />
          <input
            type="datetime-local"
            className="form-control form-control-sm"
            style={{ width: 'auto' }}
            aria-label="To"
            value={until}
            onChange={e => reset(setUntil)(e.target.value)}
            data-testid="payments-audit-until-input"
          />
        </div>
        {error && (
          <div className="alert alert-danger py-2" role="alert" data-testid="payments-audit-error">
            {error}
          </div>
        )}
        {page.events.length === 0 ? (
          !loading && (
            <EmptyState
              icon="fa-clipboard-list"
              title="No payment audit events"
              body="No payment records match these filters in the VP Audit Log."
            />
          )
        ) : (
          <div className="table-responsive">
            <table className="table table-sm table-hover mb-0" data-testid="payments-audit-table">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Stage</th>
                  <th scope="col">Surface</th>
                  <th scope="col">Amount</th>
                  <th scope="col">Detail</th>
                  <th scope="col">Trace id</th>
                </tr>
              </thead>
              <tbody>
                {page.events.map((event, index) => {
                  const details = event.event.payment_event;
                  const key = event.event_id ?? `${event.timestamp}-${index}`;
                  return (
                    <tr key={key} data-testid={`payments-audit-row-${key}`}>
                      <td className="small">{formatDateTime(new Date(event.timestamp), true)}</td>
                      <td>
                        <Badge
                          value={stageLabel(details.stage)}
                          tone={STAGE_TONE[details.stage] ?? 'secondary'}
                          size="sm"
                        />
                      </td>
                      <td>
                        {event.surface_id ? (
                          <Link to={`/surfaces/${encodeURIComponent(event.surface_id)}`}>
                            {event.surface_id}
                          </Link>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td>
                        {details.amount
                          ? `${details.amount}${details.currency ? ` ${details.currency}` : ''}`
                          : '—'}
                      </td>
                      <td className="small text-break">
                        {details.error ??
                          (details.remote_status ? `HTTP ${details.remote_status}` : '—')}
                        {event.vp_fingerprint && (
                          <div className="text-muted" title="Fingerprint of the signed credential">
                            <code>{event.vp_fingerprint}</code>
                          </div>
                        )}
                      </td>
                      <td className="small">
                        {event.trace_id ? <code>{event.trace_id}</code> : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {page.total_pages > 1 && (
          <div className="d-flex align-items-center justify-content-end gap-2 mt-3">
            <AppButton
              variant="secondary"
              size="sm"
              disabled={page.page <= 1 || loading}
              onClick={() => setPageNumber(page.page - 1)}
              data-testid="payments-audit-prev-button"
            >
              Previous
            </AppButton>
            <span className="small" data-testid="payments-audit-page">
              Page {page.page} of {page.total_pages}
            </span>
            <AppButton
              variant="secondary"
              size="sm"
              disabled={page.page >= page.total_pages || loading}
              onClick={() => setPageNumber(page.page + 1)}
              data-testid="payments-audit-next-button"
            >
              Next
            </AppButton>
          </div>
        )}
      </div>
    </div>
  );
};

export default PaymentAuditTab;
