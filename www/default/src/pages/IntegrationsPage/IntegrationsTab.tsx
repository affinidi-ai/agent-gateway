import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import FieldHelp from '../../components/shared/FieldHelp';
import { DOCS_URL } from '../../config/docs';
import { usePermissions } from '../../context/PermissionsContext';
import { useLimitGuard } from '../../hooks/useLimitGuard';
import { deleteIntegration, Integration, testIntegration } from '../../integrationsApi';
import { integrationPath, ROUTES } from '../../routes';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import { IntegrationDefinitions } from './useIntegrationDefinitions';

const STICKY_ERROR = { autoRemove: false };

interface IntegrationsTabProps extends IntegrationDefinitions {
  searchTerm: string;
  onChanged: () => void;
}

const matches = (term: string, ...texts: (string | undefined)[]) =>
  texts.some(text => text?.toLowerCase().includes(term));

const IntegrationsTab: React.FC<IntegrationsTabProps> = ({
  integrations,
  endpoints,
  eventSets,
  searchTerm,
  onChanged,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const { guard, balloonNode } = useLimitGuard();
  const [testingId, setTestingId] = useState<string | null>(null);
  const canEdit = hasPermission('integrations.edit');
  const canDelete = hasPermission('integrations.delete');

  const endpointOf = (integration: Integration) =>
    endpoints.find(endpoint => endpoint.id === integration.endpoint_id);
  const eventSetOf = (integration: Integration) =>
    eventSets.find(eventSet => eventSet.id === integration.event_set_id);

  const term = searchTerm.trim().toLowerCase();
  const shown = integrations.filter(
    integration =>
      !term ||
      matches(
        term,
        integration.name,
        integration.description,
        endpointOf(integration)?.name,
        endpointOf(integration)?.type,
        eventSetOf(integration)?.name
      )
  );

  const sendTest = async (integration: Integration) => {
    setTestingId(integration.id);
    try {
      const result = await testIntegration(integration.id);
      const destination = endpointOf(integration)?.name ?? 'its endpoint';
      showToast('success', `Test message for ${result.event_type} sent to ${destination}`);
    } catch (failure) {
      showToast('error', `Test failed: ${getErrorMessage(failure)}`, STICKY_ERROR);
    } finally {
      setTestingId(null);
    }
  };

  const remove = async (integration: Integration) => {
    try {
      await deleteIntegration(integration.id);
      onChanged();
    } catch (failure) {
      showToast('error', `Delete failed: ${getErrorMessage(failure)}`, STICKY_ERROR);
    }
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-bell" aria-hidden="true"></i> Integrations
        </h6>
        {canEdit && (
          <>
            <AppButton
              variant="primary"
              size="md"
              className="shadow-sm"
              onClick={e => guard('integrations', () => navigate(ROUTES.INTEGRATION_NEW), e)}
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
            body="An integration sends the events of an event set to an endpoint: email, Slack, a webhook or a stream. Add one to hear when gateways change, users sign in or policies deny requests."
            docsHref={DOCS_URL.integrations}
          />
        ) : shown.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No integrations match your filter.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '28%' }}>Name</th>
                  <th style={{ width: '22%' }}>Endpoint</th>
                  <th style={{ width: '22%' }}>Event set</th>
                  <th style={{ width: '10%' }}>Status</th>
                  {(canEdit || canDelete) && (
                    <th style={{ width: '18%' }}>
                      Actions{' '}
                      <FieldHelp testId="field-help-integration-test-action" ariaLabel="About Test">
                        Test sends one real message for the first event of the event set, filled
                        with sample values. It is delivered, not simulated.
                      </FieldHelp>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {shown.map(integration => {
                  const endpoint = endpointOf(integration);
                  const eventSet = eventSetOf(integration);
                  return (
                    <tr
                      key={integration.id}
                      onClick={
                        canEdit ? () => navigate(integrationPath(integration.id)) : undefined
                      }
                      style={canEdit ? { cursor: 'pointer' } : undefined}
                    >
                      <td>
                        <strong>{integration.name}</strong>
                        {integration.description && (
                          <div className="small text-muted">{integration.description}</div>
                        )}
                      </td>
                      <td>
                        {endpoint ? (
                          <>
                            {endpoint.name}{' '}
                            <span className="badge text-bg-secondary">{endpoint.type}</span>
                          </>
                        ) : (
                          <span className="text-danger">Missing endpoint</span>
                        )}
                      </td>
                      <td>
                        {eventSet ? (
                          <>
                            {eventSet.name}
                            <div className="small text-muted">
                              {eventSet.events.length} event
                              {eventSet.events.length === 1 ? '' : 's'}
                            </div>
                          </>
                        ) : (
                          <span className="text-danger">Missing event set</span>
                        )}
                      </td>
                      <td>
                        <span
                          className={`badge ${integration.status === 'active' ? 'text-bg-success' : 'text-bg-secondary'}`}
                        >
                          {integration.status}
                        </span>
                      </td>
                      {(canEdit || canDelete) && (
                        <td onClick={e => e.stopPropagation()}>
                          <div className="d-flex gap-2 align-items-center">
                            {canEdit && (
                              <>
                                <AppButton
                                  variant="secondary"
                                  size="sm"
                                  onClick={() => sendTest(integration)}
                                  disabled={testingId === integration.id}
                                  title="Send a test message"
                                  aria-label={`Test integration ${integration.name}`}
                                >
                                  {testingId === integration.id ? (
                                    <span
                                      className="spinner-border spinner-border-sm"
                                      role="status"
                                      aria-hidden="true"
                                    ></span>
                                  ) : (
                                    <i className="fas fa-paper-plane" aria-hidden="true"></i>
                                  )}
                                </AppButton>
                                <AppButton
                                  variant="outline-primary"
                                  size="sm"
                                  onClick={() => navigate(integrationPath(integration.id))}
                                  title="Edit"
                                  aria-label={`Edit integration ${integration.name}`}
                                >
                                  <i className="fas fa-edit" aria-hidden="true"></i>
                                </AppButton>
                              </>
                            )}
                            {canDelete && (
                              <DeleteButton
                                onDelete={() => remove(integration)}
                                title="Delete integration"
                                aria-label={`Delete integration ${integration.name}`}
                              />
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default IntegrationsTab;
