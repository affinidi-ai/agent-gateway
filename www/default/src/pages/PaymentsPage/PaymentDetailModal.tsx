import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { OUTCOME_META, formatLedgerAmount, rowDate } from './ledger';
import PaymentCaseStatus from './PaymentCaseStatus';
import { settlementFields } from './settlementFields';
import { usePaymentRow } from './usePaymentRow';

interface Props {
  paymentId: string;
  onClose: () => void;
  /** Shows the audit events of the payment's trace id. */
  onShowAudit?: (traceId: string) => void;
}

const optional = (
  label: string,
  value: React.ReactNode,
  testId: string
): Array<[string, React.ReactNode]> =>
  value === undefined || value === null || value === ''
    ? []
    : [
        [
          label,
          <span key={testId} data-testid={testId}>
            {value}
          </span>,
        ],
      ];

const PaymentDetailModal: React.FC<Props> = ({ paymentId, onClose, onShowAudit }) => {
  const { row, error, loading, reload } = usePaymentRow(paymentId);

  const caseStatus: Array<[string, React.ReactNode]> =
    row?.outcome === 'held'
      ? [
          [
            'Case status',
            <PaymentCaseStatus
              key="case-status"
              report={row.case_status}
              refreshing={loading}
              onRefresh={reload}
            />,
          ],
        ]
      : [];

  const fields: Array<[string, React.ReactNode]> = row
    ? [
        ['Payment id', <code key="id">{row.id}</code>],
        ['When', rowDate(row)?.toLocaleString() ?? '—'],
        ...optional('Reason', row.reason, 'payments-detail-reason'),
        ...optional(
          'Updated at',
          row.updated_at ? new Date(row.updated_at).toLocaleString() : undefined,
          'payments-detail-updated-at'
        ),
        ['Surface', `${row.surface_id}${row.variant ? `$${row.variant}` : ''}`],
        ['Payment gateway', row.payment_gateway_id],
        ['Payment surface', row.payment_surface_id],
        ['Tool / method', row.resource ?? '—'],
        ['Rail', row.rail ?? '—'],
        ['Amount', formatLedgerAmount(row)],
        ...settlementFields(row),
        ['Case id', row.case_id ? <code key="case">{row.case_id}</code> : '—'],
        ...caseStatus,
        [
          'Receipt reference',
          row.receipt_reference ? <code key="rcpt">{row.receipt_reference}</code> : '—',
        ],
        ['VC fingerprint', row.vc_fingerprint ? <code key="vc">{row.vc_fingerprint}</code> : '—'],
        ['Latency', `${row.latency_ms} ms`],
        ['Remote status', row.remote_status ?? '—'],
        [
          'Trace id',
          row.trace_id ? (
            <span key="trace">
              <code>{row.trace_id}</code>
              {onShowAudit && (
                <AppButton
                  variant="link"
                  size="sm"
                  className="p-0 ms-2 text-primary"
                  onClick={() => onShowAudit(row.trace_id as string)}
                  data-testid="payments-detail-audit-link"
                >
                  Audit events
                </AppButton>
              )}
            </span>
          ) : (
            '—'
          ),
        ],
        ...optional(
          'Idempotency key',
          row.idempotency_key ? <code>{row.idempotency_key}</code> : undefined,
          'payments-detail-idempotency-key'
        ),
        ...optional(
          'Settle timeout',
          row.settle_timeout_ms !== undefined ? `${row.settle_timeout_ms} ms` : undefined,
          'payments-detail-settle-timeout'
        ),
        ...optional(
          'Caller (hashed)',
          row.caller_principal ? (
            <span title="A peppered hash of the authenticated caller, not the caller itself">
              <code>{row.caller_principal}</code>
            </span>
          ) : undefined,
          'payments-detail-caller-principal'
        ),
      ]
    : [];

  const meta = row ? (OUTCOME_META[row.outcome] ?? OUTCOME_META.unavailable) : null;

  return (
    <div
      className="modal show d-block"
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="payment-detail-title"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
      data-testid="payments-detail-modal"
    >
      <div className="modal-dialog modal-lg modal-dialog-scrollable">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="payment-detail-title">
              Payment details {meta && <Badge value={meta.label} tone={meta.tone} size="sm" />}
            </h5>
            <button
              type="button"
              className="btn-close"
              onClick={onClose}
              aria-label="Close"
              data-testid="payments-detail-dismiss-button"
            />
          </div>
          <div className="modal-body">
            {error && (
              <div
                className={`alert alert-danger${row ? ' mb-3' : ' mb-0'}`}
                role="alert"
                data-testid="payments-detail-error"
              >
                {error}
              </div>
            )}
            {meta?.note && (
              <div className="alert alert-warning mb-3" data-testid="payments-detail-outcome-note">
                {meta.note}
              </div>
            )}
            {row ? (
              <dl className="row mb-0">
                {fields.map(([label, value]) => (
                  <React.Fragment key={label}>
                    <dt className="col-sm-4">{label}</dt>
                    <dd className="col-sm-8 text-break">{value}</dd>
                  </React.Fragment>
                ))}
              </dl>
            ) : (
              !error && (
                <div className="text-center py-4">
                  <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                </div>
              )
            )}
          </div>
          <div className="modal-footer">
            <AppButton
              variant="secondary"
              size="sm"
              onClick={onClose}
              data-testid="payments-detail-close-button"
            >
              Close
            </AppButton>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PaymentDetailModal;
