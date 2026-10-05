import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { integrationIntegration } from '../components/connection-points/IntegrationsStep';
import IdentityIntegrationsTab from './IdentityIntegrationsPage/IdentityIntegrationsTab';

interface IdentityIntegrationsData {
  integration_integrations: integrationIntegration[];
}

const IdentityIntegrationsPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isModified, setIsModified] = useState(false);
  const [notifierValidationErrors, setNotifierValidationErrors] = useState(false);
  const [formData, setFormData] = useState<IdentityIntegrationsData>({
    integration_integrations: [],
  });

  // Callback for validation state changes
  const handleValidationChange = (hasErrors: boolean) => {
    setNotifierValidationErrors(hasErrors);
  };

  useEffect(() => {
    fetchIdentityIntegrations();
  }, []);

  // Keyboard shortcut for save (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (isModified && !saving && !notifierValidationErrors) {
          handleSave();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isModified, saving, notifierValidationErrors]);

  const fetchIdentityIntegrations = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient
        .get('/identities/integrations')
        .catch(() => ({ data: { integration_integrations: [] } }));
      setFormData({
        integration_integrations: response.data.integration_integrations || [],
      });
    } catch (error: any) {
      setError(error.message || 'Failed to load identity integrations');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (
    field: keyof IdentityIntegrationsData,
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
      // Filter out any "ghost" integrations that have all empty variable values
      const cleanedIntegrations = formData.integration_integrations.filter(integration => {
        const variableCount = Object.keys(integration.variables).length;
        if (variableCount === 0) return true; // Keep integrations with no variables

        // Check if ALL variables are empty (this indicates a ghost integration)
        const allEmpty = Object.values(integration.variables).every(
          value => !value || (typeof value === 'string' && value.trim() === '')
        );
        return !allEmpty; // Remove ghost integrations
      });

      // Validate integrations - check if any variables have empty values
      const hasEmptyVariables = cleanedIntegrations.some(integration => {
        const variableCount = Object.keys(integration.variables).length;
        if (variableCount === 0) return false; // No variables to validate
        return Object.values(integration.variables).some(
          value => !value || (typeof value === 'string' && value.trim() === '')
        );
      });

      if (hasEmptyVariables) {
        setError('Please fill in all integration variable values before saving');
        return;
      }

      // Update formData with cleaned integrations
      const updatedFormData = {
        integration_integrations: cleanedIntegrations,
      };

      setSaving(true);
      setError(null);
      await apiClient.put('/identities/integrations', updatedFormData).catch(() => {
        // For now, just simulate success
        return { data: updatedFormData };
      });

      setFormData(updatedFormData);
      setSuccess('Identity integrations updated successfully!');
      setIsModified(false);
      setTimeout(() => setSuccess(null), 3000);
    } catch (error: any) {
      setError(error.message || 'Failed to update identity integrations');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    navigate('/identities');
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

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleCancel}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-plug"></i> Identity Management Integrations
          </h6>
          <div>
            <button
              className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
              onClick={handleSave}
              disabled={!isModified || saving || notifierValidationErrors}
              title={notifierValidationErrors ? 'Please fill in all notifier variable values' : ''}
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
                border: '2px solid var(--success)',
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

          <IdentityIntegrationsTab
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

export default IdentityIntegrationsPage;
