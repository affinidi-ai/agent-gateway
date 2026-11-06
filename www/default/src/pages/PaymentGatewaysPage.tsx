import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import { pingPaymentGateway } from '../components/payment-gateways/pingPaymentGateway';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { DOCS_URL } from '../config/docs';
import { ROUTES, paymentGatewayPath, paymentGatewayResumePath } from '../routes';
import { getErrorMessage } from '../utils/apiError';
import type { GatewayListItem } from '../utils/gateways';
import PaymentGatewaysTable from './PaymentGatewaysPage/PaymentGatewaysTable';
import {
  matchesPaymentGateway,
  usePaymentGateways,
} from './PaymentGatewaysPage/usePaymentGateways';

interface PaymentGatewaysPageProps {
  /** The Connections page's shared filter; the page then shows no filter of its own. */
  externalSearchTerm?: string;
  onCountChange?: (filtered: number, total: number) => void;
  /** The Connections tab banner, where the Connect button is rendered. */
  actionsContainer?: HTMLElement | null;
}

const PaymentGatewaysPage: React.FC<PaymentGatewaysPageProps> = ({
  externalSearchTerm,
  onCountChange,
  actionsContainer,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('payment_gateways.edit');
  const canDelete = hasPermission('payment_gateways.delete');
  const { gateways, loading, loadError, remove } = usePaymentGateways();
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [pinging, setPinging] = useState<Record<string, boolean>>({});
  const effectiveSearchTerm = externalSearchTerm ?? searchTerm;
  const isEmbedded = externalSearchTerm !== undefined;

  const filtered = useMemo(
    () => gateways.filter(gateway => matchesPaymentGateway(gateway, effectiveSearchTerm)),
    [gateways, effectiveSearchTerm]
  );

  useEffect(() => {
    onCountChange?.(filtered.length, gateways.length);
  }, [filtered.length, gateways.length, onCountChange]);

  const connect = useCallback(() => navigate(ROUTES.PAYMENT_GATEWAY_CONNECT), [navigate]);
  const { guard, balloonNode } = useLimitGuard();

  const handlePing = useCallback(async (gateway: GatewayListItem) => {
    setPinging(prev => ({ ...prev, [gateway.id]: true }));
    const result = await pingPaymentGateway(gateway.id, gateway.name);
    setPinging(prev => ({ ...prev, [gateway.id]: false }));
    setSuccess(result.ok ? result.message : null);
    setError(result.ok ? null : result.message);
  }, []);

  const handleDelete = useCallback(
    async (gateway: GatewayListItem) => {
      try {
        await remove(gateway.id);
        setError(null);
        setSuccess(`Payment gateway "${gateway.name}" deleted`);
      } catch (err) {
        setSuccess(null);
        setError(getErrorMessage(err, 'Failed to delete payment gateway'));
      }
    },
    [remove]
  );

  const connectButton = canEdit ? (
    <AppButton
      variant="primary"
      size="md"
      onClick={e => guard('connections.paymentgateways', connect, e)}
      iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
      data-testid="payment-gateways-connect-button"
    >
      Connect Payment Gateway
    </AppButton>
  ) : null;

  const shownError = error ?? loadError;

  return (
    <div className={isEmbedded ? '' : 'container-fluid'} data-testid="page-payment-gateways">
      {balloonNode}
      {!isEmbedded && (
        <div className="mb-4">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Payment Gateways..."
          />
        </div>
      )}
      {actionsContainer && connectButton && createPortal(connectButton, actionsContainer)}
      {shownError && (
        <div
          className="alert alert-danger alert-dismissible fade show"
          role="alert"
          data-testid="payment-gateways-error-alert"
        >
          {shownError}
          {error && (
            <button
              type="button"
              className="btn-close"
              onClick={() => setError(null)}
              aria-label="Close"
              data-testid="payment-gateways-error-dismiss-button"
            />
          )}
        </div>
      )}
      {success && (
        <div
          className="alert alert-success alert-dismissible fade show"
          role="status"
          data-testid="payment-gateways-success-alert"
        >
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
            data-testid="payment-gateways-success-dismiss-button"
          />
        </div>
      )}
      {loading ? (
        <div className="text-center py-5">
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading</span>
          </div>
        </div>
      ) : gateways.length === 0 ? (
        <div className="card shadow mb-4">
          <div className="card-body" data-testid="payment-gateways-empty-state">
            <EmptyState
              icon="fa-credit-card"
              title="Connect a payment gateway"
              body="A payment gateway is an agent-pay gateway that takes payments for your surfaces: it issues the payment challenge, verifies and settles the payment and returns the receipt. Connect with the Connection Point Link and secret its administrator shares; agent-pay's administrator then approves the connection."
              ctaLabel={canEdit ? 'Connect Payment Gateway' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? connect : undefined}
              ctaTestId="payment-gateways-empty-connect-button"
              docsHref={DOCS_URL.payments}
            />
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-credit-card"></i> Payment Gateways
                <Badge
                  value={filtered.length}
                  suffix={effectiveSearchTerm ? ` of ${gateways.length}` : undefined}
                  className="ms-2"
                  ariaLabel={`${filtered.length}${effectiveSearchTerm ? ` of ${gateways.length}` : ''} payment gateways`}
                />
              </h6>
              {!actionsContainer && connectButton}
            </div>
          </div>
          <div className="card-body">
            {filtered.length === 0 ? (
              <div className="text-center text-muted py-4" data-testid="payment-gateways-no-match">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className="mb-0">No payment gateways match your search.</p>
              </div>
            ) : (
              <PaymentGatewaysTable
                gateways={filtered}
                canEdit={canEdit}
                canDelete={canDelete}
                pinging={pinging}
                onOpen={id => navigate(paymentGatewayPath(id))}
                onResume={id => navigate(paymentGatewayResumePath(id))}
                onPing={handlePing}
                onDelete={handleDelete}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default PaymentGatewaysPage;
