import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import { AppButton } from '../components/shared/AppButton';
import { DeleteButton } from '../components/shared/DeleteButton';
import { EmptyState } from '../components/shared/EmptyState';
import FieldHelp from '../components/shared/FieldHelp';
import {
  extractTemplateVariablesFromObject,
  createTestVariables,
  getNotifierTestSuccessMessage,
} from '../utils/templateVariables';
import TestNotifierModal from '../components/TestNotifierModal';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';

interface Integration {
  id: string;
  name: string;
  description: string;
  type: string;
  category?: string;
  configuration: any;
  content: any;
  status: string;
  created_at: string;
}

const IntegrationsPage: React.FC = () => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [testingNotifierId, setTestingNotifierId] = useState<string | null>(null);
  const [showTestModal, setShowTestModal] = useState(false);
  const [testNotifier, setTestNotifier] = useState<Integration | null>(null);
  const [testVariables, setTestVariables] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ message: string; isSuccess: boolean } | null>(
    null
  );

  // Filter integrations based on search term
  const filteredIntegrations = integrations.filter(
    integration =>
      searchTerm === '' ||
      integration.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      integration.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      integration.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch integrations
      const response = await apiClient.get('/integrations');
      setIntegrations(response.data);
    } catch (error: any) {
      console.error('Error fetching integrations:', error);
      setError(error.message || 'Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteIntegration = async (id: string) => {
    try {
      await apiClient.delete(`/integrations/${id}`);
      setIntegrations(prev => prev.filter(n => n.id !== id));
    } catch (error: any) {
      console.error('Failed to delete integration:', error);
      setError(error.response?.data?.message || error.message || 'Failed to delete integration');
    }
  };

  const handleTestIntegration = async (e: React.MouseEvent, integration: Integration) => {
    e.stopPropagation();

    // Extract template variables from content
    const variables = extractTemplateVariablesFromObject(integration.content);

    // Clear any previous test results
    setTestResult(null);

    // Always show modal to allow user to see test results
    setTestNotifier(integration);
    setTestVariables(createTestVariables(variables));
    setShowTestModal(true);
  };

  const sendTestNotification = async (
    integration: Integration,
    variables: Record<string, string>
  ) => {
    // Clear previous test result
    setTestResult(null);

    try {
      setTestingNotifierId(integration.id);
      setError(null);

      const payload = {
        type: integration.type,
        configuration: integration.configuration,
        content: integration.content,
        variables,
      };

      await apiClient.post('/integrations/test', payload);

      // Show success message based on type
      const successMessage = getNotifierTestSuccessMessage(integration.type);

      setTestResult({ message: successMessage, isSuccess: true });
    } catch (error: any) {
      console.error('Failed to send test notification:', error);
      const errorMessage =
        error.response?.data?.message || error.message || 'Failed to send test notification';
      setTestResult({ message: errorMessage, isSuccess: false });
      setError(errorMessage);
    } finally {
      setTestingNotifierId(null);
    }
  };

  const handleTestModalSubmit = () => {
    if (testNotifier) {
      sendTestNotification(testNotifier, testVariables);
    }
  };

  const renderIntegrationsList = () => (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-bell"></i> Integrations{' '}
          {filteredIntegrations.length > 0 && (
            <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
              {filteredIntegrations.length}
            </span>
          )}
        </h6>
        {hasPermission('mcp_proxies.edit') && (
          <>
            <AppButton
              variant="primary"
              size="md"
              className="shadow-sm"
              onClick={e =>
                guard('integrations', () => navigate('/integrations/integrations/wizard'), e)
              }
              iconStart={<i className="fas fa-plus fa-sm me-2" aria-hidden="true" />}
            >
              Add Integration
            </AppButton>
            {balloonNode}
          </>
        )}
      </div>
      <div className="card-body">
        {integrations.length === 0 ? (
          <EmptyState
            icon="fa-bell"
            title="Add your first integration"
            body="Integrations push gateway events to external systems: email, Slack, or webhooks. Add one to get alerts when Agent Surfaces go down or policies deny requests."
            docsHref={DOCS_URL.integrations}
          />
        ) : filteredIntegrations.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No Integrations match your filter.</p>
          </div>
        ) : (
          <div className="table-responsive">
            .
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '18%' }}>Name</th>
                  <th style={{ width: '22%' }}>Description</th>
                  <th style={{ width: '10%' }}>Category</th>
                  <th style={{ width: '10%' }}>Type</th>
                  <th style={{ width: '10%' }}>Status</th>
                  <th style={{ width: '12%' }}>Created</th>
                  <th style={{ width: '18%' }}>
                    Actions{' '}
                    <FieldHelp testId="field-help-integration-test-action" ariaLabel="About Test">
                      Sends a real test notification using the values you provide. This isn't a dry
                      run: it will actually be delivered.
                    </FieldHelp>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredIntegrations.map(integration => (
                  <tr
                    key={integration.id}
                    onClick={() => navigate(`/integrations/integrations/${integration.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <strong>{integration.name}</strong>
                    </td>
                    <td>{integration.description}</td>
                    <td>
                      <span className="badge text-bg-secondary">
                        {(integration.category || 'general').toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge badge-${
                          integration.type === 'email'
                            ? 'primary'
                            : integration.type === 'slack'
                              ? 'info'
                              : integration.type === 'webhook'
                                ? 'warning'
                                : integration.type === 'stream'
                                  ? 'info'
                                  : 'secondary'
                        }`}
                      >
                        {integration.type.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge badge-${integration.status === 'active' ? 'success' : 'secondary'}`}
                      >
                        {integration.status.toUpperCase()}
                      </span>
                    </td>
                    <td>{formatDateTime(integration.created_at, true)}</td>
                    <td className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                      {(integration.type === 'email' ||
                        integration.type === 'slack' ||
                        integration.type === 'webhook' ||
                        integration.type === 'stream') && (
                        <AppButton
                          variant="secondary"
                          size="sm"
                          onClick={e => handleTestIntegration(e, integration)}
                          disabled={testingNotifierId === integration.id}
                          title="Test"
                          aria-label={`Test integration ${integration.name}`}
                        >
                          {testingNotifierId === integration.id ? (
                            <span
                              className="spinner-border spinner-border-sm"
                              role="status"
                              aria-hidden="true"
                            ></span>
                          ) : (
                            <i className="fas fa-paper-plane" aria-hidden="true"></i>
                          )}
                        </AppButton>
                      )}
                      <AppButton
                        variant="outline-primary"
                        size="sm"
                        onClick={e => {
                          e.stopPropagation();
                          navigate(`/integrations/integrations/${integration.id}`);
                        }}
                        title="Edit"
                        aria-label={`Edit integration ${integration.name}`}
                      >
                        <i className="fas fa-edit" aria-hidden="true"></i>
                      </AppButton>
                      <DeleteButton
                        onDelete={() => handleDeleteIntegration(integration.id)}
                        className="btn-sm"
                        title="Delete integration"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Integrations...."
          />
        </div>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}

      {loading ? (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : (
        <>{renderIntegrationsList()}</>
      )}

      {/* Test Integration Variables Modal */}
      <TestNotifierModal
        show={showTestModal && testNotifier !== null}
        integrationName={testNotifier?.name || ''}
        variables={testVariables}
        isTesting={testingNotifierId !== null}
        testResult={testResult}
        onVariableChange={(varName, value) =>
          setTestVariables({
            ...testVariables,
            [varName]: value,
          })
        }
        onCancel={() => {
          setShowTestModal(false);
          setTestResult(null);
        }}
        onTest={handleTestModalSubmit}
      />
    </div>
  );
};

export default IntegrationsPage;
