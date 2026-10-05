import React from 'react';

import FieldHelp from '../../components/shared/FieldHelp';
import {
  ConnectionRuntimeStatus,
  errorCodeLabel,
  reconnectAtLabel,
} from '../../utils/connectionHealth';
import { formatDateTime } from '../../utils/stringUtils';

interface GatewayForm {
  name: string;
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: 'active' | 'disabled';
  exposed_channels?: string[];
}

interface OverviewTabProps {
  form: GatewayForm;
  setForm: (form: GatewayForm) => void;
  createdAt?: string;
  updatedAt?: string;
  runtimeStatus?: ConnectionRuntimeStatus | null;
  isEditMode: boolean;
  isSelfGateway: boolean;
  saving: boolean;
  id?: string;
  handleSubmit: (e: React.FormEvent) => void;
  handleDelete: () => void;
  onNavigate: () => void;
}

const OverviewTab: React.FC<OverviewTabProps> = ({
  form,
  setForm,
  createdAt,
  updatedAt,
  runtimeStatus,
  isEditMode,
  isSelfGateway,
  saving,
  id,
  handleSubmit,
  handleDelete,
  onNavigate,
}) => {
  return (
    <>
      {isSelfGateway && (
        <div className="alert alert-info" role="alert">
          <i className="fas fa-info-circle me-2"></i>
          This is the self gateway and cannot be deleted. It can be edited to update its details.
        </div>
      )}
      {runtimeStatus && runtimeStatus.status !== 'connected' && (
        <div className="alert alert-danger" role="alert">
          <div className="d-flex align-items-center mb-1">
            <i className="fas fa-exclamation-circle me-2"></i>
            <strong>Connection failed</strong>
          </div>
          <div>{runtimeStatus.error_message || errorCodeLabel(runtimeStatus.error_code)}</div>
          {reconnectAtLabel(runtimeStatus) && (
            <div className="small text-muted mt-1">{reconnectAtLabel(runtimeStatus)}</div>
          )}
          {typeof runtimeStatus.consecutive_failures === 'number' &&
            runtimeStatus.consecutive_failures > 0 && (
              <div className="small text-muted">
                Failed attempts: {runtimeStatus.consecutive_failures}
              </div>
            )}
          <div className="small text-muted">
            {runtimeStatus.last_active_at
              ? `Last active: ${formatDateTime(runtimeStatus.last_active_at, true)}`
              : 'Never connected'}
          </div>
          {runtimeStatus.original_error && (
            <details className="mt-1">
              <summary className="small text-muted" style={{ cursor: 'pointer' }}>
                Error details
              </summary>
              <code style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}>
                {runtimeStatus.original_error}
              </code>
            </details>
          )}
        </div>
      )}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-info-circle"></i> Gateway Information
            </h6>
          </div>
        </div>
        <div className="card-body">
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="name" className="form-label">
                Name *
              </label>
              <input
                type="text"
                className="form-control"
                id="name"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                required
                autoFocus={!isEditMode}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="description" className="form-label">
                Description
              </label>
              <input
                className="form-control"
                id="description"
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="did" className="form-label">
                Gateway DID
              </label>
              <input
                type="text"
                className="form-control"
                id="did"
                value={form.did}
                onChange={e => setForm({ ...form, did: e.target.value })}
                required
                disabled={isEditMode}
                readOnly={isEditMode}
              />
              {isEditMode && (
                <small className="form-text text-muted">
                  The DID cannot be changed after creation
                </small>
              )}
            </div>

            {isEditMode && (
              <>
                <div className="mb-3">
                  <label htmlFor="id" className="form-label">
                    Gateway Id
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    id="id"
                    value={id}
                    disabled
                    readOnly
                  />
                  <small className="form-text text-muted">
                    Internal identifier for this gateway
                  </small>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="gateway-created" className="form-label">
                      Created
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="gateway-created"
                      value={createdAt ? formatDateTime(createdAt, true) : 'N/A'}
                      disabled
                      readOnly
                    />
                  </div>
                  <div className="col-md-6 mb-3">
                    <label htmlFor="gateway-updated" className="form-label">
                      Last Updated
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="gateway-updated"
                      value={updatedAt ? formatDateTime(updatedAt, true) : 'N/A'}
                      disabled
                      readOnly
                    />
                  </div>
                </div>
              </>
            )}
            <div className="mb-4">
              <div className="form-check">
                <input
                  disabled={isSelfGateway}
                  type="checkbox"
                  className="form-check-input"
                  id="status"
                  checked={form.status === 'active'}
                  onChange={e =>
                    setForm({ ...form, status: e.target.checked ? 'active' : 'disabled' })
                  }
                />
                <label className="form-check-label" htmlFor="status">
                  {!isSelfGateway && (
                    <span>
                      <strong>Gateway Enabled</strong> - When unchecked, the gateway will be
                      disabled
                    </span>
                  )}
                  {isSelfGateway && (
                    <span>
                      <strong>Gateway Enabled</strong> - This Gateway cannot be disabled
                    </span>
                  )}
                  {!isSelfGateway && (
                    <FieldHelp testId="field-help-gateway-status" ariaLabel="About Gateway Enabled">
                      Disabling stops this gateway from accepting or routing any traffic over the
                      fabric (the gateway-to-gateway network this appliance participates in) until
                      it's re-enabled.
                    </FieldHelp>
                  )}

                  {form.status === 'disabled' && (
                    <span className="badge text-bg-warning ms-2">
                      <i className="fas fa-power-off"></i> DISABLED
                    </span>
                  )}
                </label>
              </div>
            </div>
          </form>
        </div>
      </div>
    </>
  );
};

export default OverviewTab;
