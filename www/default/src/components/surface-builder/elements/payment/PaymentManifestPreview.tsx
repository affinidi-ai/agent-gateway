import React from 'react';
import type { PaymentManifest } from '../../../../types';
import { describePointDetail, formatMoney } from './manifest';

interface PaymentManifestPreviewProps {
  manifest: PaymentManifest | null;
  source: 'live' | 'snapshot' | null;
  loading: boolean;
  error: string | null;
  drift: string[];
  onRefresh: () => void;
}

const PaymentManifestPreview: React.FC<PaymentManifestPreviewProps> = ({
  manifest,
  source,
  loading,
  error,
  drift,
  onRefresh,
}) => (
  <div className="config-section" data-testid="payment-manifest-preview">
    <div className="d-flex justify-content-between align-items-center">
      <label className="mb-0">Price and payment methods</label>
      <button
        type="button"
        className="btn btn-link btn-sm p-0"
        style={{ fontSize: '10px' }}
        onClick={onRefresh}
        disabled={loading}
        data-testid="payment-manifest-refresh-button"
      >
        <i className="fas fa-rotate me-1" aria-hidden="true" />
        {loading ? 'Loading…' : 'Refresh'}
      </button>
    </div>

    {error && (
      <div className="text-warning small mt-1" role="alert" data-testid="payment-manifest-error">
        <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
        {error}
      </div>
    )}

    {drift.length > 0 && (
      <div
        className="alert alert-warning py-1 px-2 mt-1 mb-1"
        style={{ fontSize: '11px' }}
        role="status"
        data-testid="payment-manifest-drift"
      >
        <i className="fas fa-code-compare me-1" aria-hidden="true" />
        agent-pay has changed this surface since it was saved. Save to update the snapshot.
        <ul className="mb-0 ps-3">
          {drift.map(d => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      </div>
    )}

    {!manifest && !loading && !error && (
      <div className="text-muted small mt-1" data-testid="payment-manifest-empty">
        No payment manifest. Check that this is a payment surface on agent-pay.
      </div>
    )}

    {manifest && (
      <div style={{ fontSize: '11px', lineHeight: '18px' }} className="mt-1">
        <div>
          <strong data-testid="payment-manifest-payable">
            {manifest.payable?.name || manifest.payable?.id}
          </strong>{' '}
          <span className="text-muted">
            {source === 'snapshot' ? '(saved snapshot)' : '(live from agent-pay)'}
          </span>
        </div>
        <div data-testid="payment-manifest-amount">
          <strong>Price:</strong> {formatMoney(manifest.amount)}
        </div>
        {(manifest.payment_points ?? []).length > 0 && (
          <table className="table table-sm mb-1 mt-1" style={{ fontSize: '11px' }}>
            <thead>
              <tr>
                <th scope="col">Method</th>
                <th scope="col">Protocol</th>
                <th scope="col">Credential</th>
              </tr>
            </thead>
            <tbody>
              {manifest.payment_points.map(p => (
                <tr key={p.id} data-testid={`payment-manifest-point-${p.id}`}>
                  <td title={describePointDetail(p)}>{p.label}</td>
                  <td>{p.protocol}</td>
                  <td>
                    <code>{p.credential}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {(manifest.variants ?? []).length > 0 && (
          <div data-testid="payment-manifest-variants">
            <strong>Variants:</strong>
            <ul className="list-unstyled mb-0 ps-2">
              {(manifest.variants ?? []).map(v => (
                <li key={v.alias}>
                  <code>${v.alias}</code> {v.name}
                  {v.amount ? ` · ${formatMoney(v.amount)}` : ''}
                  {v.is_default ? ' (default)' : ''}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    )}
  </div>
);

export default PaymentManifestPreview;
