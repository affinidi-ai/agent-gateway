import React, { useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { DeleteButton } from '../components/shared/DeleteButton';
import { apiClient } from '../api';
import { ROUTES } from '../routes';
import { getErrorMessage } from '../utils/apiError';
import { showToast } from '../utils/toaster';
import HealthSection from './PaymentGatewayDetailPage/HealthSection';
import OverviewSection from './PaymentGatewayDetailPage/OverviewSection';
import PaymentSurfacesSection from './PaymentGatewayDetailPage/PaymentSurfacesSection';
import UsedBySection from './PaymentGatewayDetailPage/UsedBySection';
import { usePaymentGateway } from './PaymentGatewayDetailPage/usePaymentGateway';

const tabAttrs = (key: string) => ({ 'data-testid': `payment-gateway-tab-${key}` });

const PaymentGatewayDetailPage: React.FC = () => {
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('payment_gateways.edit');
  const { gateway, loading, loadError, update } = usePaymentGateway(id);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const back = () => navigate(ROUTES.PAYMENT_GATEWAYS_TAB);

  const handleDelete = async () => {
    try {
      await apiClient.delete(`/payment-gateways/${encodeURIComponent(id)}`);
      showToast('success', 'Payment gateway deleted');
      back();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to delete payment gateway'));
    }
  };

  const shownError = error ?? loadError;

  return (
    <div className="container-fluid" data-testid="page-payment-gateway">
      <div className="mb-3">
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={back}
          aria-label="Back to Payment Gateways"
          data-testid="payment-gateway-back-button"
        >
          <i className="fas fa-arrow-left" aria-hidden="true"></i>
        </button>
      </div>
      {shownError && (
        <div
          className="alert alert-danger alert-dismissible fade show"
          role="alert"
          data-testid="payment-gateway-error-alert"
        >
          <i className="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>
          {shownError}
          {error && (
            <button
              type="button"
              className="btn-close"
              onClick={() => setError(null)}
              aria-label="Close"
              data-testid="payment-gateway-error-dismiss-button"
            />
          )}
        </div>
      )}
      {loading && !gateway ? (
        <div className="text-center py-4">
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading</span>
          </div>
        </div>
      ) : (
        gateway && (
          <div className="card shadow mb-4 channel-editor-card">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-credit-card" aria-hidden="true"></i> Payment Gateway:{' '}
                {gateway.name}
              </h6>
              {hasPermission('payment_gateways.delete') && (
                <DeleteButton
                  onDelete={handleDelete}
                  variant="danger"
                  title="Delete this payment gateway"
                  data-testid="payment-gateway-delete-button"
                >
                  Delete
                </DeleteButton>
              )}
            </div>
            <div className="card-body-channel-editor">
              <Tabs
                activeKey={activeTab}
                onSelect={k => setActiveTab(k || 'overview')}
                className="mb-3 custom-channel-tabs"
                mountOnEnter
              >
                <Tab
                  eventKey="overview"
                  tabAttrs={tabAttrs('overview')}
                  title={
                    <>
                      <i className="fas fa-info-circle"></i> Overview
                    </>
                  }
                >
                  <OverviewSection
                    gateway={gateway}
                    canEdit={canEdit}
                    update={update}
                    onError={setError}
                  />
                </Tab>
                <Tab
                  eventKey="surfaces"
                  tabAttrs={tabAttrs('surfaces')}
                  title={
                    <>
                      <i className="fas fa-receipt"></i> Payment Surfaces
                    </>
                  }
                >
                  <PaymentSurfacesSection gatewayId={gateway.id} />
                </Tab>
                <Tab
                  eventKey="used-by"
                  tabAttrs={tabAttrs('used-by')}
                  title={
                    <>
                      <i className="fas fa-project-diagram"></i> Used by
                    </>
                  }
                >
                  <UsedBySection gatewayId={gateway.id} />
                </Tab>
                <Tab
                  eventKey="health"
                  tabAttrs={tabAttrs('health')}
                  title={
                    <>
                      <i className="fas fa-heartbeat"></i> Health
                    </>
                  }
                >
                  <HealthSection gateway={gateway} canPing={canEdit} />
                </Tab>
              </Tabs>
            </div>
          </div>
        )
      )}
    </div>
  );
};

export default PaymentGatewayDetailPage;
