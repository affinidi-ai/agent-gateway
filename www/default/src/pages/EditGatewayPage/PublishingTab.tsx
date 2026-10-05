import React from 'react';

interface GatewayForm {
  name: string;
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: 'active' | 'disabled';
  exposed_channels?: string[];
}

interface PublishingTabProps {
  form: GatewayForm;
  setForm: (form: GatewayForm) => void;
  allChannels: any[];
  savingExposedChannels: boolean;
  success: string | null;
  setSuccess: (success: string | null) => void;
  handleToggleExposedChannel: (channelId: string) => void;
  handleSaveExposedChannels: () => void;
}

const PublishingTab: React.FC<PublishingTabProps> = ({
  form,
  allChannels,
  savingExposedChannels,
  success,
  setSuccess,
  handleToggleExposedChannel,
  handleSaveExposedChannels,
}) => {
  return (
    <>
      {success && (
        <div
          key={`success-${Date.now()}`}
          className="alert alert-success alert-dismissible fade show"
          style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: 9999,
            minWidth: '400px',
            fontSize: '14px',
            fontWeight: 'bold',
            border: '2px solid #151615ff',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
          }}
        >
          <i className="fas fa-check-circle me-2"></i>
          <strong>Success!</strong> {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            title="Close notification"
            aria-label="Close"
          />
        </div>
      )}

      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-filter"></i> Exposed Surfaces Configuration
            </h6>
          </div>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            Select which local surfaces should be visible to this remote gateway when it queries for
            available surfaces.
            {(form.exposed_channels?.length || 0) === 0 && (
              <span className="text-info ms-1">
                <strong>(Currently all active surfaces are exposed)</strong>
              </span>
            )}
          </p>

          {allChannels.length === 0 ? (
            <div className="alert alert-info mb-0">
              <i className="fas fa-info-circle me-2"></i>
              No local surfaces available. Create surfaces first to configure exposure.
            </div>
          ) : (
            <>
              <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                {allChannels.map(channel => {
                  const isExposed = (form.exposed_channels || []).includes(channel.config_id);
                  return (
                    <div key={channel.config_id} className="form-check mb-2">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        id={`channel-${channel.config_id}`}
                        checked={isExposed}
                        onChange={() => handleToggleExposedChannel(channel.config_id)}
                      />
                      <label
                        className="form-check-label"
                        htmlFor={`channel-${channel.config_id}`}
                        style={{ cursor: 'pointer' }}
                      >
                        <strong>{channel.name}</strong>
                        {channel.description && (
                          <small className="text-muted d-block">{channel.description}</small>
                        )}
                        <code className="text-muted" style={{ fontSize: '0.7rem' }}>
                          {channel.config_id}
                        </code>
                      </label>
                    </div>
                  );
                })}
              </div>

              <div className="mt-3 pt-3 border-top">
                <button
                  className="btn btn-sm btn-primary"
                  onClick={handleSaveExposedChannels}
                  disabled={savingExposedChannels}
                >
                  {savingExposedChannels ? (
                    <>
                      <span
                        className="spinner-border spinner-border-sm me-2"
                        role="status"
                        aria-hidden="true"
                      ></span>
                      Saving...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-save me-2"></i> Save Exposed Surfaces
                    </>
                  )}
                </button>
                <span className="ms-3 text-muted small">
                  {(form.exposed_channels?.length || 0) === 0
                    ? ' All active surfaces will be exposed'
                    : ` ${form.exposed_channels?.length} of ${allChannels.length} surfaces selected`}
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default PublishingTab;
