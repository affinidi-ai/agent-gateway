import React, { useMemo, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useSearchParams } from 'react-router-dom';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import InfoBanner from '../components/shared/InfoBanner';
import { DOCS_URL } from '../config/docs';
import { PAYMENT_OUTCOMES, type PaymentLedgerRow, type PaymentOutcome } from '../types';
import PaymentOutcomeChart from './PaymentsPage/PaymentOutcomeChart';
import PaymentLedgerTable from './PaymentsPage/PaymentLedgerTable';
import PaymentDetailModal from './PaymentsPage/PaymentDetailModal';
import LegacyPaymentsTab from './PaymentsPage/LegacyPaymentsTab';
import PaymentAuditTab from './PaymentsPage/PaymentAuditTab';
import { OUTCOME_META } from './PaymentsPage/ledger';
import { usePaymentLedger } from './PaymentsPage/usePaymentLedger';

const matchesText = (row: PaymentLedgerRow, needle: string) =>
  [
    row.surface_id,
    row.variant,
    row.payment_surface_id,
    row.resource,
    row.case_id,
    row.receipt_reference,
    row.amount,
    row.currency,
    row.rail,
  ].some(v => typeof v === 'string' && v.toLowerCase().includes(needle));

const PaymentsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const surfaceId = searchParams.get('surface_id') || undefined;
  const [outcome, setOutcome] = useState<PaymentOutcome | ''>('');
  const [filterText, setFilterText] = useState('');
  const [bucketSeconds, setBucketSeconds] = useState(900);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [tab, setTab] = useState<string>('ledger');
  const [auditTraceId, setAuditTraceId] = useState('');
  const { rows, total, legacyRows, refreshing, stale, error, dismissError, refresh } =
    usePaymentLedger({
      surfaceId,
      outcome,
    });

  const needle = filterText.trim().toLowerCase();
  const visibleRows = useMemo(
    () => (needle ? rows.filter(r => matchesText(r, needle)) : rows),
    [rows, needle]
  );

  const ledger = (
    <>
      <PaymentOutcomeChart
        rows={visibleRows}
        bucketSeconds={bucketSeconds}
        onBucketChange={setBucketSeconds}
      />
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-money-bill-wave me-2" aria-hidden="true" />
            Payment ledger
            <Badge
              value={visibleRows.length}
              className="ms-2"
              ariaLabel={`${visibleRows.length} payments shown`}
            />
            {total > rows.length && (
              <Badge
                value={total}
                tone="secondary"
                prefix="of "
                className="ms-1"
                ariaLabel={`${rows.length} of ${total} payments loaded`}
              />
            )}
          </h6>
        </div>
        <div className="card-body">
          <InfoBanner
            title="How payments work"
            testIdPrefix="payments-overview"
            docLink={DOCS_URL.payments}
          >
            <p className="mb-0">
              Surfaces charge callers through a connected <strong>agent-pay</strong> gateway. Each
              row is one payment check: <strong>Paid</strong> means agent-pay returned a receipt and
              the request went upstream; <strong>Challenge</strong> means the caller was asked to
              pay; <strong>Held</strong> means agent-pay is holding the payment for review under the
              case id shown; <strong>Rejected</strong> and <strong>Unavailable</strong> mean the
              request was refused; <strong>Unconfirmed</strong> means agent-pay did not answer, so
              the payment may have been taken: the caller can retry the same request with the same
              credential within 2 minutes.
            </p>
          </InfoBanner>
          {stale && (
            <div
              className="alert alert-warning py-2"
              role="status"
              data-testid="payments-stale-note"
            >
              The last refresh failed, so these rows may be out of date.
            </div>
          )}
          {rows.length === 0 && !refreshing && (outcome || surfaceId) ? (
            <EmptyState
              icon="fa-filter"
              title="No payments match this filter"
              body={`There are no ${outcome ? `${OUTCOME_META[outcome].label} ` : ''}payments${
                surfaceId ? ` for surface ${surfaceId}` : ''
              }. Choose All outcomes or another surface to see more.`}
            />
          ) : rows.length === 0 && !refreshing ? (
            <EmptyState
              icon="fa-money-bill-wave"
              title="No payments yet"
              body="Payments appear here once a surface with a Payment element starts charging callers through agent-pay."
              docsHref={DOCS_URL.payments}
            />
          ) : visibleRows.length === 0 ? (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className="mb-0">No payments match your search.</p>
            </div>
          ) : (
            <PaymentLedgerTable rows={visibleRows} onViewDetails={setDetailId} />
          )}
        </div>
      </div>
    </>
  );

  return (
    <div className="container-fluid" data-testid="page-payments">
      <div className="d-sm-flex align-items-center justify-content-between mb-4 gap-2">
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <SearchInput
            value={filterText}
            onChange={setFilterText}
            placeholder="Filter Payments..."
            data-testid="payments-filter-input"
          />
          <select
            className="form-select form-select-sm"
            style={{ width: 'auto' }}
            aria-label="Outcome"
            value={outcome}
            onChange={e => setOutcome(e.target.value as PaymentOutcome | '')}
            data-testid="payments-outcome-filter"
          >
            <option value="">All outcomes</option>
            {PAYMENT_OUTCOMES.map(o => (
              <option key={o} value={o}>
                {OUTCOME_META[o].label}
              </option>
            ))}
          </select>
          {surfaceId && (
            <span className="small text-muted" data-testid="payments-surface-filter">
              Surface <code>{surfaceId}</code>
            </span>
          )}
        </div>
        <AppButton
          variant="primary"
          size="md"
          className="shadow-sm"
          onClick={refresh}
          loading={refreshing}
          loadingLabel="Refreshing..."
          disabled={refreshing}
          data-testid="payments-refresh-button"
          iconStart={<i className="fas fa-sync-alt fa-sm me-1" aria-hidden="true" />}
        >
          Refresh
        </AppButton>
      </div>

      {error && (
        <div
          className="alert alert-danger alert-dismissible fade show"
          role="alert"
          data-testid="payments-error-alert"
        >
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={dismissError}
            aria-label="Close"
            data-testid="payments-error-dismiss-button"
          />
        </div>
      )}

      <Tabs
        activeKey={tab}
        onSelect={key => setTab(key ?? 'ledger')}
        id="payments-tabs"
        className="mb-3 custom-channel-tabs"
      >
        <Tab eventKey="ledger" title={<span data-testid="payments-ledger-tab">Ledger</span>}>
          {ledger}
        </Tab>
        <Tab eventKey="audit" title={<span data-testid="payments-audit-tab">Audit trail</span>}>
          {tab === 'audit' && (
            <PaymentAuditTab
              surfaceId={surfaceId}
              traceId={auditTraceId}
              onTraceIdChange={setAuditTraceId}
            />
          )}
        </Tab>
        {legacyRows.length > 0 && (
          <Tab
            eventKey="legacy"
            title={
              <span data-testid="payments-legacy-tab">
                Legacy x402/MPP <Badge value={legacyRows.length} tone="secondary" size="sm" />
              </span>
            }
          >
            <LegacyPaymentsTab rows={legacyRows} />
          </Tab>
        )}
      </Tabs>

      {detailId && (
        <PaymentDetailModal
          paymentId={detailId}
          onClose={() => setDetailId(null)}
          onShowAudit={traceId => {
            setAuditTraceId(traceId);
            setDetailId(null);
            setTab('audit');
          }}
        />
      )}
    </div>
  );
};

export default PaymentsPage;
