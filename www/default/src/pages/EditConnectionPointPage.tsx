import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Tab, Tabs } from 'react-bootstrap';
import { apiClient } from '../api';
import { integrationIntegration } from '../components/connection-points/IntegrationsStep';
import ConnectionPointOverviewTab from './EditConnectionPointPage/ConnectionPointOverviewTab';
import ConnectionPointMetadataTab from './EditConnectionPointPage/ConnectionPointMetadataTab';
import ConnectionPointIntegrationsTab from './EditConnectionPointPage/ConnectionPointIntegrationsTab';
import { DeleteButton } from '../components/shared/DeleteButton';
import { showToast } from '../utils/toaster';
import { useSafeNavigate } from '../hooks/useSafeNavigate';

interface ConnectionPoint {
  id: string;
  gateway_id: string;
  mediator_id: string;
  name: string;
  description: string;
  oob_url: string;
  use_count: number;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  expires_at?: string;
  cp_type?: 'user' | 'system';
  secret?: string;
  exposed_channels?: string[];
  integrations?: integrationIntegration[];
  enabled?: boolean;
}

interface ConnectionPointFormData {
  name: string;
  description: string;
  enabled: boolean;
  integration_integrations: integrationIntegration[];
}

const EditConnectionPointPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const [connectionPoint, setConnectionPoint] = useState<ConnectionPoint | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isModified, setIsModified] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [gatewayData, setGatewayData] = useState<any>(null);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [testingIntegrations, setTestingIntegrations] = useState(false);
  const [testResults, setTestResults] = useState<
    Array<{ integration_id: string; success: boolean; message: string }>
  >([]);
  const [testVariables, setTestVariables] = useState<
    Array<{ integration_id: string; variables: Record<string, string> }>
  >([]);
  const [integrationValidationErrors, setIntegrationValidationErrors] = useState(false);
  const [formData, setFormData] = useState<ConnectionPointFormData>({
    name: '',
    description: '',
    enabled: true,
    integration_integrations: [],
  });

  // Callback for validation state changes
  const handleValidationChange = (hasErrors: boolean) => {
    setIntegrationValidationErrors(hasErrors);
  };

  useEffect(() => {
    if (id) {
      fetchConnectionPoint();
    }
    // Fetch integrations for test modal
    apiClient
      .get('/integrations')
      .then(res => setIntegrations(res.data))
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

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
  }, [isModified, saving, deleting, integrationValidationErrors]);

  const fetchConnectionPoint = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get(`/connection-points/${id}`);
      const data = response.data;
      setConnectionPoint(data);
      setFormData({
        name: data.name,
        description: data.description || '',
        enabled: data.enabled !== undefined ? data.enabled : true,
        integration_integrations: data.integrations || [],
      });

      // Fetch gateway data for runtime variables
      if (data.gateway_id) {
        try {
          const gatewayResponse = await apiClient.get(`/gateways/${data.gateway_id}`);
          setGatewayData(gatewayResponse.data);
        } catch (err) {
          console.error('Failed to fetch gateway data:', err);
        }
      }
    } catch (error: any) {
      setError(error.message || 'Failed to load connection point');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (
    field: keyof ConnectionPointFormData,
    value: string | boolean | integrationIntegration[]
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
          value => !value || value.trim() === ''
        );
        return !allEmpty; // Remove ghost integrations
      });

      // Validate integrations - check if any variables have empty values
      const hasEmptyVariables = cleanedIntegrations.some(integration => {
        const variableCount = Object.keys(integration.variables).length;
        if (variableCount === 0) return false; // No variables to validate
        return Object.values(integration.variables).some(value => !value || value.trim() === '');
      });

      if (hasEmptyVariables) {
        setError('Please fill in all integration variable values before saving');
        return;
      }

      // Update formData with cleaned integrations
      const updatedFormData = {
        ...formData,
        integration_integrations: cleanedIntegrations,
      };

      setSaving(true);
      setError(null);
      const response = await apiClient.put(`/connection-points/${id}`, updatedFormData);

      // Update the connection point state with the response (backend returns 'integrations' field)
      const updatedConnectionPoint = response.data;
      setConnectionPoint(updatedConnectionPoint);

      // Keep formData in sync - backend returns 'integrations', we use 'integration_integrations' in formData
      setFormData(prev => ({
        ...prev,
        integration_integrations: updatedConnectionPoint.integrations || [],
      }));

      setIsModified(false);
      showToast('success', 'Connection point updated!');
      navigate('/connections?tab=gateways');
    } catch (error: any) {
      setError(error.message || 'Failed to update connection point');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    navigate('/connections?tab=gateways');
  };

  const handleDelete = async () => {
    if (!connectionPoint) return;

    try {
      setDeleting(true);
      await apiClient.delete(`/connection-points/${id}`);
      navigate('/connections?tab=gateways');
    } catch (error: any) {
      setError(error.message || 'Failed to delete connection point');
    } finally {
      setDeleting(false);
    }
  };

  const handleCopyUrl = () => {
    if (connectionPoint) {
      navigator.clipboard.writeText(connectionPoint.oob_url);
      //setSuccess('Connection point link copied to clipboard!');
      setTimeout(() => setSuccess(null), 2000);
    }
  };

  const handleCopySecret = () => {
    if (connectionPoint?.secret) {
      navigator.clipboard.writeText(connectionPoint.secret);
      //setSuccess('Connection secret copied to clipboard!');
      setTimeout(() => setSuccess(null), 2000);
    }
  };

  const handleTest = () => {
    if (formData.integration_integrations.length === 0) {
      setError('No integrations configured to test');
      return;
    }

    // Get runtime variable values
    const runtimeValues = getRuntimeVariableValues();

    // Initialize test variables with runtime variable references resolved
    const initialTestVars = formData.integration_integrations.map(integration => {
      const resolvedVariables: Record<string, string> = {};

      // Resolve runtime variable references in each configured variable
      for (const [key, value] of Object.entries(integration.variables)) {
        // Check if value is a runtime variable reference like ${CP_NAME} or ${CP_NAME:Label}
        // Match any content inside ${} to be flexible
        const match = value.match(/^\$\{([^:}]+)(?::[^}]*)?\}$/);
        const varName = match ? match[1].trim() : null;
        if (varName && varName in runtimeValues) {
          // Replace with actual runtime value
          resolvedVariables[key] = runtimeValues[varName];
        } else {
          // Use literal value
          resolvedVariables[key] = value;
        }
      }

      return {
        integration_id: integration.integration_id,
        variables: resolvedVariables,
      };
    });

    setTestVariables(initialTestVars);
    setShowTestModal(true);
    setTestResults([]);
  };

  const handleSendTest = async () => {
    setTestingIntegrations(true);
    setTestResults([]);

    const results: Array<{ integration_id: string; success: boolean; message: string }> = [];

    for (const testVar of testVariables) {
      try {
        const integration = integrations.find(n => n.id === testVar.integration_id);
        if (!integration) {
          results.push({
            integration_id: testVar.integration_id,
            success: false,
            message: 'Integration not found',
          });
          continue;
        }

        // Use test variable values directly (no runtime resolution needed, they're already resolved)
        const payload = {
          type: integration.type,
          configuration: integration.configuration,
          content: integration.content,
          variables: testVar.variables,
        };

        await apiClient.post('/integrations/test', payload);

        results.push({
          integration_id: testVar.integration_id,
          success: true,
          message: 'Test notification sent successfully',
        });
      } catch (error: any) {
        results.push({
          integration_id: testVar.integration_id,
          success: false,
          message:
            error.response?.data?.message || error.message || 'Failed to send test notification',
        });
      }
    }

    setTestResults(results);
    setTestingIntegrations(false);
  };

  const getRuntimeVariableValues = (): Record<string, string> => {
    const now = new Date();
    return {
      CP_ID: connectionPoint?.id || 'cp_123456',
      CP_NAME: formData.name || connectionPoint?.name || 'Connection Point',
      CP_DESCRIPTION: formData.description || connectionPoint?.description || 'No description',
      GATEWAY: gatewayData?.name || 'Gateway Name',
      GATEWAY_ID: connectionPoint?.gateway_id || 'gw_123456',
      TIMESTAMP: now.toISOString(),
      MESSAGE_ID: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    };
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

  if (error && !connectionPoint) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
        <button className="btn btn-secondary" onClick={handleCancel}>
          Back to Gateways
        </button>
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
            <i className="fas fa-edit"></i> Edit Connection Point Details: {connectionPoint?.name}
            {!formData.enabled && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off"></i> DISABLED
              </span>
            )}
            {connectionPoint?.cp_type === 'system' && (
              <span className="badge text-bg-secondary ms-2">
                <i className="fas fa-cog"></i> SYSTEM
              </span>
            )}
          </h6>
          <div>
            <button
              className="btn btn-sm btn-info me-2"
              onClick={handleTest}
              disabled={formData.integration_integrations.length === 0}
              title="Test integrations with current values"
            >
              <i className="fas fa-vial"></i> Test Integrations
            </button>
            <button
              className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
              onClick={handleSave}
              disabled={!isModified || saving || integrationValidationErrors}
              title={
                integrationValidationErrors ? 'Please fill in all integration variable values' : ''
              }
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {saving ? ' Saving...' : ' Save'}
            </button>
            <DeleteButton
              onDelete={handleDelete}
              className="me-2"
              title="Delete this connection point"
              disabled={deleting}
              variant="danger"
            >
              Delete
            </DeleteButton>
          </div>
        </div>

        <div className="card-body-channel-editor">
          <p className="text-muted mb-3">
            This connection point is the invitation link a remote gateway used, or will use, to
            connect to this appliance.
          </p>
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

          <Tabs
            activeKey={activeTab}
            onSelect={k => setActiveTab(k || 'overview')}
            className="mb-3 custom-channel-tabs"
          >
            <Tab
              eventKey="overview"
              title={
                <>
                  <i className="fas fa-info-circle"></i> Overview
                </>
              }
            >
              <ConnectionPointOverviewTab
                formData={formData}
                connectionPoint={connectionPoint}
                onInputChange={handleInputChange}
                onCopyUrl={handleCopyUrl}
                onCopySecret={handleCopySecret}
              />
            </Tab>
            <Tab
              eventKey="mediator"
              title={
                <>
                  <i className="fas fa-database"></i> Metadata
                </>
              }
            >
              <ConnectionPointMetadataTab connectionPoint={connectionPoint} />
            </Tab>
            <Tab
              eventKey="integrations"
              title={
                <>
                  <i className="fas fa-bell"></i> Integrations
                </>
              }
            >
              <ConnectionPointIntegrationsTab
                integrations={formData.integration_integrations}
                onIntegrationsChange={integrations =>
                  handleInputChange('integration_integrations', integrations)
                }
                onValidationChange={handleValidationChange}
              />
            </Tab>
          </Tabs>
        </div>
      </div>

      {/* Test Modal */}
      {showTestModal && (
        <>
          <div
            className="modal-backdrop fade show"
            onClick={() => setShowTestModal(false)}
            style={{ zIndex: 1040 }}
          ></div>
          <div className="modal fade show" style={{ display: 'block', zIndex: 1050 }} tabIndex={-1}>
            <div className="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">
                    <i className="fas fa-vial me-2"></i>
                    Test Integrations
                  </h5>
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setShowTestModal(false)}
                    title="Close"
                    aria-label="Close"
                  />
                </div>
                <div className="modal-body">
                  <div className="alert alert-info">
                    <i className="fas fa-info-circle me-2"></i>
                    <strong>Test Mode:</strong> This will send actual notifications using the
                    configured variables. Runtime variables will be substituted with current values
                    where available.
                  </div>

                  {testResults.length === 0 ? (
                    <>
                      <h6 className="mb-3">Edit variable values for testing:</h6>
                      {testVariables.map((testVar, index) => {
                        const integration = integrations.find(n => n.id === testVar.integration_id);
                        if (!integration) return null;

                        return (
                          <div key={index} className="mb-4 p-3 border rounded">
                            <h6 className="font-weight-bold mb-3">
                              <i className="fas fa-bell me-2"></i>
                              {integration.name}
                              <span className="badge text-bg-primary ms-2">{integration.type}</span>
                            </h6>
                            <div className="mb-3">
                              {Object.entries(testVar.variables).map(([key, value]) => (
                                <div key={key} className="mb-2">
                                  <label className="mb-1 small font-weight-bold">
                                    <code>{key}</code>
                                  </label>
                                  <input
                                    type="text"
                                    className="form-control form-control-sm"
                                    value={value}
                                    onChange={e => {
                                      const updated = [...testVariables];
                                      updated[index].variables[key] = e.target.value;
                                      setTestVariables(updated);
                                    }}
                                    placeholder={`Enter value for ${key}`}
                                  />
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </>
                  ) : (
                    <>
                      <h6 className="mb-3">Test Results:</h6>
                      {testResults.map((result, index) => {
                        const integration = integrations.find(n => n.id === result.integration_id);
                        return (
                          <div
                            key={index}
                            className={`alert ${result.success ? 'alert-success' : 'alert-danger'} mb-2`}
                          >
                            <i
                              className={`fas ${result.success ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2`}
                            ></i>
                            <strong>{integration?.name || 'Unknown Integration'}</strong> -{' '}
                            {result.message}
                          </div>
                        );
                      })}
                    </>
                  )}
                </div>
                <div className="modal-footer">
                  {testResults.length === 0 ? (
                    <>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => setShowTestModal(false)}
                        disabled={testingIntegrations}
                      >
                        <i className="fas fa-times me-1"></i>
                        Cancel
                      </button>
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={handleSendTest}
                        disabled={testingIntegrations}
                      >
                        {testingIntegrations ? (
                          <>
                            <i className="fas fa-spinner fa-spin me-1"></i>
                            Sending...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-paper-plane me-1"></i>
                            Send Test Notifications
                          </>
                        )}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => setShowTestModal(false)}
                    >
                      <i className="fas fa-times me-1"></i>
                      Close
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default EditConnectionPointPage;
