import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import GatewayStatusCell from '../../components/gateways/GatewayStatusCell';
import PaymentGatewayOfferSummary from '../../components/payment-gateways/PaymentGatewayOfferSummary';
import {
  GATEWAY_INFO_PROBLEM_TEXT,
  usePaymentGatewayInfo,
} from '../../components/payment-gateways/usePaymentGatewayInfo';
import { AppButton } from '../../components/shared/AppButton';
import { paymentGatewayResumePath } from '../../routes';
import { getErrorMessage } from '../../utils/apiError';
import { isGatewayPending, type GatewayListItem } from '../../utils/gateways';
import { formatDateTime } from '../../utils/stringUtils';
import { showToast } from '../../utils/toaster';

interface OverviewSectionProps {
  gateway: GatewayListItem;
  canEdit: boolean;
  update: (
    fields: Partial<Pick<GatewayListItem, 'name' | 'description' | 'status'>>
  ) => Promise<void>;
  onError: (message: string | null) => void;
}

const OverviewSection: React.FC<OverviewSectionProps> = ({ gateway, canEdit, update, onError }) => {
  const [name, setName] = useState(gateway.name);
  const [description, setDescription] = useState(gateway.description ?? '');
  const [saving, setSaving] = useState(false);

  const active = gateway.status === 'active';
  const { info, loading: infoLoading, problem } = usePaymentGatewayInfo(gateway.id, active);

  const dirty = name.trim() !== gateway.name || description.trim() !== (gateway.description ?? '');

  const run = async (
    fields: Partial<Pick<GatewayListItem, 'name' | 'description' | 'status'>>,
    done: string
  ) => {
    setSaving(true);
    onError(null);
    try {
      await update(fields);
      showToast('success', done);
    } catch (err) {
      onError(getErrorMessage(err, 'Failed to update the payment gateway'));
    } finally {
      setSaving(false);
    }
  };

  const handleSave = (event: React.FormEvent) => {
    event.preventDefault();
    if (!name.trim()) {
      onError('Name is required');
      return;
    }
    run({ name: name.trim(), description: description.trim() }, 'Payment gateway updated');
  };

  return (
    <>
      {isGatewayPending(gateway) && (
        <div
          className="alert alert-warning"
          role="alert"
          data-testid="payment-gateway-pending-note"
        >
          <i className="fas fa-hourglass-half me-2" aria-hidden="true"></i>
          This payment gateway is not active yet: agent-pay&apos;s administrator must approve the
          connection.{' '}
          {canEdit && (
            <Link
              to={paymentGatewayResumePath(gateway.id)}
              className="alert-link"
              data-testid="payment-gateway-verify-button"
            >
              Verify the connection
            </Link>
          )}
        </div>
      )}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-info-circle" aria-hidden="true"></i> Payment Gateway Information
          </h6>
        </div>
        <div className="card-body">
          <form onSubmit={handleSave}>
            <div className="mb-3">
              <label htmlFor="payment-gateway-name" className="form-label">
                Name *
              </label>
              <input
                type="text"
                className="form-control"
                id="payment-gateway-name"
                value={name}
                onChange={e => setName(e.target.value)}
                disabled={!canEdit}
                required
                data-testid="payment-gateway-name-input"
              />
            </div>
            <div className="mb-3">
              <label htmlFor="payment-gateway-description" className="form-label">
                Description
              </label>
              <input
                className="form-control"
                id="payment-gateway-description"
                value={description}
                onChange={e => setDescription(e.target.value)}
                disabled={!canEdit}
                data-testid="payment-gateway-description-input"
              />
            </div>
            <dl className="row mb-3">
              <dt className="col-sm-3">DID</dt>
              <dd className="col-sm-9">
                <code data-testid="payment-gateway-did">{gateway.did}</code>
              </dd>
              <dt className="col-sm-3">Id</dt>
              <dd className="col-sm-9">
                <code>{gateway.id}</code>
              </dd>
              <dt className="col-sm-3">Status</dt>
              <dd className="col-sm-9" data-testid="payment-gateway-status">
                <GatewayStatusCell gateway={gateway} />
              </dd>
              <dt className="col-sm-3">Offers</dt>
              <dd className="col-sm-9">
                {!active ? (
                  <span className="text-muted">Shown once the payment gateway is active</span>
                ) : infoLoading ? (
                  <span className="text-muted">Loading…</span>
                ) : info ? (
                  <PaymentGatewayOfferSummary info={info} testId="payment-gateway-offer" />
                ) : (
                  <span className="text-warning" data-testid="payment-gateway-offer-error">
                    {GATEWAY_INFO_PROBLEM_TEXT[problem ?? 'failed']}
                  </span>
                )}
              </dd>
              <dt className="col-sm-3">Created</dt>
              <dd className="col-sm-9">{formatDateTime(gateway.created_at, true)}</dd>
              <dt className="col-sm-3">Last updated</dt>
              <dd className="col-sm-9">{formatDateTime(gateway.updated_at, true)}</dd>
            </dl>
            {canEdit && (
              <div className="d-flex gap-2">
                <AppButton
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={!dirty}
                  loading={saving}
                  loadingLabel="Saving"
                  iconStart={<i className="fas fa-save me-1" aria-hidden="true" />}
                  data-testid="payment-gateway-save-button"
                >
                  Save
                </AppButton>
                {(gateway.status === 'active' || gateway.status === 'disabled') && (
                  <AppButton
                    variant={active ? 'outline-danger' : 'outline-primary'}
                    size="sm"
                    disabled={saving}
                    onClick={() =>
                      run(
                        { status: active ? 'disabled' : 'active' },
                        active ? 'Payment gateway disabled' : 'Payment gateway enabled'
                      )
                    }
                    iconStart={<i className="fas fa-power-off me-1" aria-hidden="true" />}
                    data-testid="payment-gateway-toggle-status-button"
                  >
                    {active ? 'Disable' : 'Enable'}
                  </AppButton>
                )}
              </div>
            )}
          </form>
        </div>
      </div>
    </>
  );
};

export default OverviewSection;
