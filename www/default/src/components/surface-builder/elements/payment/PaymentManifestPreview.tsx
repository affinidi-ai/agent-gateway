import React, { useState } from 'react';
import type { PaymentManifest, PaymentPoint } from '../../../../types';
import { describePointDetail, formatMoney, paymentLogoUrl } from './manifest';

/** The point's logo from its payment gateway, or a generic icon when there is none or it fails to load. */
const PaymentPointLogo: React.FC<{ point: PaymentPoint; testIdPrefix: string }> = ({
  point,
  testIdPrefix,
}) => {
  const [failed, setFailed] = useState(false);
  const url = paymentLogoUrl(point);
  if (!url || failed) {
    return (
      <i
        className={`fas ${point.protocol === 'mpp' ? 'fa-credit-card' : 'fa-coins'} text-muted me-1`}
        aria-hidden="true"
        data-testid={`${testIdPrefix}-point-icon-${point.id}`}
      />
    );
  }
  return (
    <img
      src={url}
      alt=""
      width={16}
      height={16}
      className="me-1 align-text-bottom"
      onError={() => setFailed(true)}
      data-testid={`${testIdPrefix}-point-logo-${point.id}`}
    />
  );
};

interface PaymentManifestPreviewProps {
  manifest: PaymentManifest | null;
  source: 'live' | 'snapshot' | null;
  loading: boolean;
  error: string | null;
  drift: string[];
  /** Without it, the preview has no Refresh button. */
  onRefresh?: () => void;
  /** Prefix of every test id, so several previews can share a page. */
  testIdPrefix?: string;
}

const PaymentManifestPreview: React.FC<PaymentManifestPreviewProps> = ({
  manifest,
  source,
  loading,
  error,
  drift,
  onRefresh,
  testIdPrefix = 'payment-manifest',
}) => (
  <div className="config-section" data-testid={`${testIdPrefix}-preview`}>
    <div className="d-flex justify-content-between align-items-center">
      <label className="mb-0">Price and payment methods</label>
      {onRefresh && (
        <button
          type="button"
          className="btn btn-link btn-sm p-0"
          style={{ fontSize: '10px' }}
          onClick={onRefresh}
          disabled={loading}
          data-testid={`${testIdPrefix}-refresh-button`}
        >
          <i className="fas fa-rotate me-1" aria-hidden="true" />
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      )}
    </div>

    {error && (
      <div className="text-warning small mt-1" role="alert" data-testid={`${testIdPrefix}-error`}>
        <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
        {error}
      </div>
    )}

    {drift.length > 0 && (
      <div
        className="alert alert-warning py-1 px-2 mt-1 mb-1"
        style={{ fontSize: '11px' }}
        role="status"
        data-testid={`${testIdPrefix}-drift`}
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
      <div className="text-muted small mt-1" data-testid={`${testIdPrefix}-empty`}>
        No payment manifest. Check that this is a payment surface on agent-pay.
      </div>
    )}

    {manifest && (
      <div style={{ fontSize: '11px', lineHeight: '18px' }} className="mt-1">
        <div>
          <strong data-testid={`${testIdPrefix}-payable`}>
            {manifest.payable?.name || manifest.payable?.id}
          </strong>{' '}
          <span className="text-muted">
            {source === 'snapshot' ? '(saved snapshot)' : '(live from agent-pay)'}
          </span>
        </div>
        <div data-testid={`${testIdPrefix}-amount`}>
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
                <tr key={p.id} data-testid={`${testIdPrefix}-point-${p.id}`}>
                  <td title={describePointDetail(p)}>
                    <PaymentPointLogo point={p} testIdPrefix={testIdPrefix} />
                    {p.label}
                  </td>
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
          <div data-testid={`${testIdPrefix}-variants`}>
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
