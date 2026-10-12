import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { getErrorMessage } from '../utils/apiError';
import { integrationIntegration } from '../components/connection-points/IntegrationsStep';
import UserIntegrationsTab from './UserIntegrationsPage/UserIntegrationsTab';

interface UserIntegrationsData {
  integration_integrations: integrationIntegration[];
}

const UserIntegrationsPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isModified, setIsModified] = useState(false);
  const [integrationValidationErrors, setIntegrationValidationErrors] = useState(false);
  const [formData, setFormData] = useState<UserIntegrationsData>({
    integration_integrations: [],
  });

  // Callback for validation state changes
  const handleValidationChange = (hasErrors: boolean) => {
    setIntegrationValidationErrors(hasErrors);
  };

  useEffect(() => {
    fetchUserIntegrations();
  }, []);

  // Keyboard shortcut for save (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (isModified && !saving && !integrationValidationErrors) {
          handleSave();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isModified, saving, integrationValidationErrors]);

  const fetchUserIntegrations = async () => {
    try {
      setLoading(true);
      setLoadError(null);
      const response = await apiClient.get('/users/integrations');
      setFormData({
        integration_integrations: response.data.integration_integrations || [],
      });
    } catch (error: unknown) {
      setLoadError(getErrorMessage(error, 'Failed to load user integrations'));
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (
    field: keyof UserIntegrationsData,
    value: integrationIntegration[]
  ) => {
    setFormData(prev => ({
      ...prev,
      [field]: value,
    }));
    setIsModified(true);
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      await apiClient.put('/users/integrations', formData);
      setSuccess('User integrations updated successfully!');
      setIsModified(false);
      setTimeout(() => setSuccess(null), 3000);
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to update user integrations'));
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    navigate('/users');
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  const backButton = (
    <div className="mb-3">
      <button className="btn btn-sm btn-secondary" onClick={handleCancel}>
        <i className="fas fa-arrow-left"></i>
      </button>
    </div>
  );

  if (loadError) {
    return (
      <div className="container-fluid">
        {backButton}
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {loadError}
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      {backButton}
      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-plug"></i> User Management Integrations
          </h6>
          <div>
            <button
              className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
              onClick={handleSave}
              disabled={!isModified || saving || integrationValidationErrors}
              data-testid="user-integrations-save-button"
              title={
                integrationValidationErrors ? 'Please fill in all integration variable values' : ''
              }
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {saving ? ' Saving...' : ' Save'}
            </button>
          </div>
        </div>

        <div className="card-body-channel-editor">
          {/* Success/Error Message - Fixed position to ensure visibility */}
          {error && (
            <div
              key={`error-${Date.now()}`}
              className="alert alert-danger alert-dismissible fade show mb-4"
              style={{
                position: 'fixed',
                top: '20px',
                right: '20px',
                zIndex: 9999,
                minWidth: '400px',
                fontSize: '14px',
                fontWeight: 'bold',
                border: '2px solid var(--danger)',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              }}
            >
              <i className="fas fa-exclamation-triangle me-2"></i>
              <strong>Error!</strong> {error}
              <button
                type="button"
                className="btn-close"
                onClick={() => setError(null)}
                title="Close notification"
                aria-label="Close"
              />
            </div>
          )}

          {success && (
            <div
              key={`success-${Date.now()}`}
              className="alert alert-success alert-dismissible fade show mb-4"
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

          <UserIntegrationsTab
            integrations={formData.integration_integrations}
            onIntegrationsChange={integrations =>
              handleInputChange('integration_integrations', integrations)
            }
            onValidationChange={handleValidationChange}
          />
        </div>
      </div>
    </div>
  );
};

export default UserIntegrationsPage;
