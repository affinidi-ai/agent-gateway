import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';
import { surfacesUsingPaymentGateway, type PaymentGatewayUse } from './usedBy';

/** The surfaces that charge through the payment gateway, by their base policy or a variant. */
const UsedBySection: React.FC<{ gatewayId: string }> = ({ gatewayId }) => {
  const [uses, setUses] = useState<PaymentGatewayUse[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .listSurfaces()
      .then(surfaces => {
        if (!cancelled) setUses(surfacesUsingPaymentGateway(surfaces, gatewayId));
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(getErrorMessage(err, 'Could not load the surfaces'));
      });
    return () => {
      cancelled = true;
    };
  }, [gatewayId]);

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-project-diagram" aria-hidden="true"></i> Used by
        </h6>
      </div>
      <div className="card-body">
        {error ? (
          <div
            className="alert alert-warning mb-0"
            role="alert"
            data-testid="payment-gateway-used-by-error"
          >
            {error}
          </div>
        ) : uses === null ? (
          <div className="spinner-border spinner-border-sm" role="status">
            <span className="visually-hidden">Loading</span>
          </div>
        ) : uses.length === 0 ? (
          <div className="text-muted" data-testid="payment-gateway-used-by-empty">
            No surface charges through this payment gateway.
          </div>
        ) : (
          <ul className="list-unstyled mb-0">
            {uses.map(use => (
              <li
                key={use.surfaceId}
                className="mb-2"
                data-testid={`payment-gateway-used-by-${use.surfaceId}`}
              >
                <Link
                  to={`/surfaces/${encodeURIComponent(use.surfaceId)}`}
                  data-testid={`payment-gateway-used-by-link-${use.surfaceId}`}
                >
                  {use.name || use.surfaceId}
                </Link>
                <span className="small text-muted ms-2">
                  {[use.base ? 'surface' : null, ...use.variants.map(alias => `variant $${alias}`)]
                    .filter(Boolean)
                    .join(', ')}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default UsedBySection;
