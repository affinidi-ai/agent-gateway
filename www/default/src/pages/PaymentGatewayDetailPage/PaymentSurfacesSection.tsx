import React, { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import PaymentManifestPreview from '../../components/surface-builder/elements/payment/PaymentManifestPreview';
import {
  surfacesErrorMessage,
  toRemoteSurfaces,
  type RemoteSurface,
} from '../../components/surface-builder/elements/_shared/useGatewaySurfaces';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';

const NO_ANSWER = 'agent-pay did not answer in time. Try Refresh.';

/** The surfaces the payment gateway exposes to this gateway, each with its manifest. */
const PaymentSurfacesSection: React.FC<{ gatewayId: string }> = ({ gatewayId }) => {
  const [surfaces, setSurfaces] = useState<RemoteSurface[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (force: boolean) => {
      setLoading(true);
      setError(null);
      try {
        const { data } = await apiClient.get<{ success?: boolean }>(
          `/payment-gateways/${encodeURIComponent(gatewayId)}/surfaces${force ? '?force_refresh=true' : ''}`
        );
        if (data && data.success === false) {
          setSurfaces([]);
          setError(NO_ANSWER);
        } else {
          setSurfaces(toRemoteSurfaces(data));
        }
      } catch (err) {
        setSurfaces([]);
        setError(surfacesErrorMessage(err));
      } finally {
        setLoading(false);
      }
    },
    [gatewayId]
  );

  useEffect(() => {
    load(false);
  }, [load]);

  return (
    <div className="card shadow-sm mb-4">
      <div className="card-header bg-light d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-receipt" aria-hidden="true"></i> Payment Surfaces
          <Badge value={surfaces.length} className="ms-2" />
        </h6>
        <AppButton
          variant="outline-primary"
          size="sm"
          onClick={() => load(true)}
          disabled={loading}
          iconStart={
            <i className={`fas fa-sync-alt me-1${loading ? ' fa-spin' : ''}`} aria-hidden="true" />
          }
          data-testid="payment-gateway-surfaces-refresh-button"
        >
          Refresh
        </AppButton>
      </div>
      <div className="card-body">
        {error && (
          <div
            className="alert alert-warning"
            role="alert"
            data-testid="payment-gateway-surfaces-error"
          >
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>
            {error}
          </div>
        )}
        {loading && surfaces.length === 0 ? (
          <div className="text-center py-4">
            <div className="spinner-border" role="status">
              <span className="visually-hidden">Loading</span>
            </div>
          </div>
        ) : (
          !error &&
          surfaces.length === 0 && (
            <div className="text-muted" data-testid="payment-gateway-surfaces-empty">
              agent-pay exposes no surface to this gateway. In agent-pay, expose a payment surface
              on the connection point this gateway connected through, then Refresh.
            </div>
          )
        )}
        <div className="row g-3">
          {surfaces.map(surface => (
            <div
              className="col-lg-6"
              key={surface.config_id}
              data-testid={`payment-gateway-surface-${surface.config_id}`}
            >
              <div className="border rounded p-2 h-100">
                <div className="d-flex justify-content-between align-items-start">
                  <div>
                    <strong>{surface.name}</strong>{' '}
                    <code className="text-muted small">{surface.config_id}</code>
                    {surface.description && (
                      <div className="small text-muted">{surface.description}</div>
                    )}
                  </div>
                  {surface.protocol && <Badge value={surface.protocol.toUpperCase()} size="sm" />}
                </div>
                <PaymentManifestPreview
                  manifest={surface.payment_manifest ?? null}
                  source="live"
                  loading={false}
                  error={null}
                  drift={[]}
                  testIdPrefix={`payment-gateway-surface-manifest-${surface.config_id}`}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PaymentSurfacesSection;
