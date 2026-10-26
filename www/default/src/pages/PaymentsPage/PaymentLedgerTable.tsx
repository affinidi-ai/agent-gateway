import React from 'react';
import { Link } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';
import type { PaymentLedgerRow } from '../../types';
import { OUTCOME_META, formatLedgerAmount, rowDate } from './ledger';

const formatWhen = (row: PaymentLedgerRow) => {
  const d = rowDate(row);
  if (!d) return '—';
  return Date.now() - d.getTime() < 3_600_000 ? timeAgo(d) : formatDateTime(d, true);
};

interface Props {
  rows: PaymentLedgerRow[];
  onViewDetails: (id: string) => void;
}

const PaymentLedgerTable: React.FC<Props> = ({ rows, onViewDetails }) => (
  <div className="table-responsive">
    <table className="table table-sm table-hover mb-0" data-testid="payments-ledger-table">
      <thead>
        <tr>
          <th scope="col">Outcome</th>
          <th scope="col">Surface</th>
          <th scope="col">Tool / method</th>
          <th scope="col">Amount</th>
          <th scope="col">Rail</th>
          <th scope="col">When</th>
          <th scope="col" style={{ textAlign: 'right' }}>
            Latency
          </th>
          <th scope="col" style={{ textAlign: 'right' }}>
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map(row => {
          const meta = OUTCOME_META[row.outcome] ?? OUTCOME_META.unavailable;
          return (
            <tr key={row.id} data-testid={`payments-row-${row.id}`}>
              <td>
                <Badge value={meta.label} tone={meta.tone} size="sm" />
                {row.outcome === 'held' && row.case_id && (
                  <div
                    className="small text-muted mt-1"
                    title={row.case_id}
                    data-testid={`payments-held-case-${row.id}`}
                  >
                    <i className="fas fa-hourglass-half me-1" aria-hidden="true" />
                    Case <code>{row.case_id}</code>
                  </div>
                )}
                {row.reason && (
                  <div
                    className="small text-muted mt-1 text-truncate"
                    style={{ maxWidth: '14rem' }}
                    title={row.reason}
                    data-testid={`payments-reason-${row.id}`}
                  >
                    {row.reason}
                  </div>
                )}
              </td>
              <td>
                <Link
                  to={`/surfaces/${encodeURIComponent(row.surface_id)}`}
                  className="text-primary"
                  data-testid={`payments-surface-link-${row.id}`}
                >
                  {row.surface_id}
                </Link>
                {row.variant && <span className="text-muted small">${row.variant}</span>}
                <div className="small text-muted" title={row.payment_gateway_id}>
                  via {row.payment_surface_id}
                </div>
              </td>
              <td>{row.resource ? <code>{row.resource}</code> : '—'}</td>
              <td>{formatLedgerAmount(row)}</td>
              <td>{row.rail ?? '—'}</td>
              <td className="small">{formatWhen(row)}</td>
              <td className="small" style={{ textAlign: 'right' }}>
                {row.latency_ms} ms
              </td>
              <td style={{ textAlign: 'right' }}>
                <AppButton
                  variant="link"
                  size="sm"
                  className="p-0 text-primary"
                  onClick={() => onViewDetails(row.id)}
                  data-testid={`payments-details-button-${row.id}`}
                  iconStart={<i className="fas fa-file-alt me-1" aria-hidden="true" />}
                >
                  Details
                </AppButton>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

export default PaymentLedgerTable;
