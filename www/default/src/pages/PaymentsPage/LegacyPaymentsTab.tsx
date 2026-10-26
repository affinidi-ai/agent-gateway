import React from 'react';
import { formatDateTime } from '../../utils/stringUtils';
import type { LegacyPaymentRow } from './legacy';

const LegacyPaymentsTab: React.FC<{ rows: LegacyPaymentRow[] }> = ({ rows }) => (
  <div className="card shadow mb-4" data-testid="payments-legacy-panel">
    <div className="card-body">
      <p className="text-muted small">
        Payments taken by this gateway&apos;s former local x402/MPP paywall. Read-only; new payments
        go through agent-pay and appear on the Ledger tab.
      </p>
      <div className="table-responsive">
        <table className="table table-sm mb-0">
          <thead>
            <tr>
              <th scope="col">Protocol</th>
              <th scope="col">Surface</th>
              <th scope="col">Status</th>
              <th scope="col">Amount</th>
              <th scope="col">When</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.key} data-testid={`payments-legacy-row-${r.key}`}>
                <td>{r.protocol}</td>
                <td>{r.surface}</td>
                <td>{r.status}</td>
                <td>{r.amount}</td>
                <td className="small">
                  {r.created_at ? formatDateTime(new Date(r.created_at * 1000), true) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  </div>
);

export default LegacyPaymentsTab;
