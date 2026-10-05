import React, { useState, useEffect } from 'react';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { useSafeNavigate } from '../hooks/useSafeNavigate';

const EditApiKeyPage: React.FC = () => {
  const { navigate } = useSafeNavigate();

  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState('');

  const [formData, setFormData] = useState({
    agent_id: '',
    client_id: '',
    labels: '',
  });

  // Created key result (shown once)
  const [createdResult, setCreatedResult] = useState<{
    key_id: string;
    secret: string;
    agent_id: string;
    client_id: string;
  } | null>(null);

  // Keyboard shortcut for saving (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (!isSaving && !createdResult) {
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSaving, createdResult]);

  const parseLabels = (input: string): Record<string, string> | undefined => {
    const labels: Record<string, string> = {};
    if (!input.trim()) return undefined;
    input.split(',').forEach(pair => {
      const [k, ...rest] = pair.split('=');
      if (k?.trim() && rest.length > 0) {
        labels[k.trim()] = rest.join('=').trim();
      }
    });
    return Object.keys(labels).length > 0 ? labels : undefined;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.agent_id.trim()) {
      setError('Agent ID is required');
      return;
    }

    if (!formData.client_id.trim()) {
      setError('Client ID is required');
      return;
    }

    setIsSaving(true);
    setError('');

    try {
      const response = await apiClient.fetch(
        `/api/v1/api-keys/${encodeURIComponent(formData.agent_id.trim())}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: formData.client_id.trim(),
            labels: parseLabels(formData.labels),
          }),
        }
      );

      if (!response.ok) {
        const err = await response.text();
        throw new Error(err || response.statusText);
      }

      const created = await response.json();
      setCreatedResult(created);
      showToast('success', 'API key created successfully');
    } catch (err: any) {
      console.error('Failed to create API key:', err);
      const errorMsg = err.message || 'Failed to create API key';
      setError(errorMsg);
      showToast('error', errorMsg);
    } finally {
      setIsSaving(false);
    }
  };

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/secrets')}
          disabled={isSaving}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-key me-2"></i>
            Create API Key
          </h1>
          <p className="text-muted mt-2">Generate a new API key for agent authentication</p>
        </div>
        {!createdResult && (
          <div>
            <button
              className="btn btn-sm btn-primary me-2"
              onClick={handleSubmit as any}
              disabled={isSaving || !formData.agent_id.trim() || !formData.client_id.trim()}
            >
              {isSaving ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-1"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Creating...
                </>
              ) : (
                <>
                  <i className="fas fa-save me-1"></i>
                  Create
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
      )}

      <div className="row">
        <div className="col-lg-8">
          {createdResult ? (
            <div className="card shadow mb-4">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-success">
                  <i className="fas fa-check-circle me-2"></i>
                  API Key Created
                </h6>
              </div>
              <div className="card-body">
                <div className="alert alert-warning">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  <strong>Copy the secret now.</strong> It will not be shown again.
                </div>

                <div className="mb-3">
                  <label className="font-weight-bold">API Key Secret</label>
                  <div className="input-group">
                    <input
                      type="text"
                      className="form-control font-monospace"
                      readOnly
                      value={createdResult.secret}
                    />
                    <button
                      className="btn btn-outline-secondary"
                      onClick={() => {
                        navigator.clipboard.writeText(createdResult.secret);
                        showToast('success', 'Copied to clipboard');
                      }}
                    >
                      <i className="fas fa-copy"></i>
                    </button>
                  </div>
                </div>

                <div className="mb-3">
                  <label className="font-weight-bold">Key ID</label>
                  <input
                    type="text"
                    className="form-control font-monospace bg-light"
                    readOnly
                    value={createdResult.key_id}
                  />
                </div>

                <div className="mb-3">
                  <label className="font-weight-bold">Agent ID</label>
                  <input
                    type="text"
                    className="form-control bg-light"
                    readOnly
                    value={createdResult.agent_id}
                  />
                </div>

                <div className="mb-3">
                  <label className="font-weight-bold">Client ID</label>
                  <input
                    type="text"
                    className="form-control bg-light"
                    readOnly
                    value={createdResult.client_id}
                  />
                </div>

                <div className="d-flex justify-content-between">
                  <button className="btn btn-primary" onClick={() => navigate('/secrets')}>
                    <i className="fas fa-arrow-left me-1"></i>
                    Back to Secrets
                  </button>
                  <button
                    className="btn btn-outline-primary"
                    onClick={() => {
                      setCreatedResult(null);
                      setFormData({ agent_id: '', client_id: '', labels: '' });
                    }}
                  >
                    <i className="fas fa-plus me-1"></i>
                    Create Another
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="card shadow mb-4">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">New API Key</h6>
              </div>
              <div className="card-body">
                <form onSubmit={handleSubmit}>
                  <div className="mb-3">
                    <label htmlFor="agent_id">
                      Agent ID <span className="text-danger">*</span>
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="agent_id"
                      value={formData.agent_id}
                      onChange={e => handleInputChange('agent_id', e.target.value)}
                      placeholder="e.g., my-agent"
                      required
                    />
                    <small className="form-text text-muted">
                      The agent this key will be scoped to
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="client_id">
                      Client ID <span className="text-danger">*</span>
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="client_id"
                      value={formData.client_id}
                      onChange={e => handleInputChange('client_id', e.target.value)}
                      placeholder="e.g., frontend-app"
                      required
                    />
                    <small className="form-text text-muted">
                      External client identifier for this key
                    </small>
                  </div>

                  <div className="mb-3">
                    <label htmlFor="labels">Labels</label>
                    <input
                      type="text"
                      className="form-control"
                      id="labels"
                      value={formData.labels}
                      onChange={e => handleInputChange('labels', e.target.value)}
                      placeholder="env=prod, team=platform"
                    />
                    <small className="form-text text-muted">
                      Comma-separated key=value pairs for categorization
                    </small>
                  </div>

                  <div className="d-flex justify-content-between align-items-center">
                    <div>
                      <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={
                          isSaving || !formData.agent_id.trim() || !formData.client_id.trim()
                        }
                      >
                        {isSaving ? (
                          <>
                            <span
                              className="spinner-border spinner-border-sm me-2"
                              role="status"
                              aria-hidden="true"
                            ></span>
                            Creating...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-key me-2"></i>
                            Create API Key
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary ms-2"
                        onClick={() => navigate('/secrets')}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="col-lg-4">
          <div className="card shadow mb-4 border-warning">
            <div className="card-body">
              <h6 className="font-weight-bold text-warning">
                <i className="fas fa-shield-alt me-2"></i>
                Security Notice
              </h6>
              <p className="mb-0" style={{ fontSize: '0.85em' }}>
                The API key secret is shown only once at creation time. Store it securely. If lost,
                you will need to rotate or create a new key.
              </p>
            </div>
          </div>

          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2"></i>
                API Key Information
              </h6>
            </div>
            <div className="card-body">
              <h6 className="font-weight-bold">What are API Keys?</h6>
              <p style={{ fontSize: '0.9em' }}>
                API keys allow client calls to be authenticated against a specific agent. They
                provide a secure way to authenticate requests without requiring interactive login.
              </p>

              <h6 className="font-weight-bold mt-3">Agent Scoping</h6>
              <p style={{ fontSize: '0.9em' }}>
                Each key is scoped to an agent. The agent ID determines which channels and
                permissions the key grants access to.
              </p>

              <h6 className="font-weight-bold mt-3">Labels</h6>
              <p style={{ fontSize: '0.9em' }}>
                Use labels to organize keys by environment, team, or purpose. Labels are key=value
                pairs like <code>env=prod</code>.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EditApiKeyPage;
