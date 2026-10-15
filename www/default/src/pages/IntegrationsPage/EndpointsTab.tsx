import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { usePermissions } from '../../context/PermissionsContext';
import { deleteEndpoint, Endpoint, testEndpoint } from '../../integrationsApi';
import { endpointPath, ROUTES } from '../../routes';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import { matches, namesOfIntegrations, STICKY_ERROR, usedByLabel } from './listHelpers';
import { IntegrationDefinitions } from './useIntegrationDefinitions';

interface EndpointsTabProps extends IntegrationDefinitions {
  searchTerm: string;
  onChanged: () => void;
}

/** Where integrations deliver: transport, destination and credentials. */
const EndpointsTab: React.FC<EndpointsTabProps> = ({
  integrations,
  endpoints,
  searchTerm,
  onChanged,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [testingId, setTestingId] = useState<string | null>(null);
  const canEdit = hasPermission('integrations.edit');
  const canDelete = hasPermission('integrations.delete');

  const term = searchTerm.trim().toLowerCase();
  const shown = endpoints.filter(
    endpoint =>
      !term || matches(term, endpoint.name, endpoint.description, endpoint.type, endpoint.status)
  );
  const usersOf = (endpoint: Endpoint) =>
    namesOfIntegrations(integrations, integration => integration.endpoint_id === endpoint.id);

  const sendTest = async (endpoint: Endpoint) => {
    setTestingId(endpoint.id);
    try {
      await testEndpoint(endpoint.id);
      showToast('success', `Test message sent to ${endpoint.name}`);
    } catch (failure) {
      showToast('error', `Test failed: ${getErrorMessage(failure)}`, STICKY_ERROR);
    } finally {
      setTestingId(null);
    }
  };

  const remove = async (endpoint: Endpoint) => {
    try {
      await deleteEndpoint(endpoint.id);
      onChanged();
    } catch (failure) {
      showToast('error', `Delete failed: ${getErrorMessage(failure)}`, STICKY_ERROR);
    }
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-plug" aria-hidden="true"></i> Endpoints
        </h6>
        {canEdit && (
          <AppButton
            variant="primary"
            size="md"
            className="shadow-sm"
            onClick={() => navigate(ROUTES.ENDPOINT_NEW)}
            iconStart={<i className="fas fa-plus fa-sm me-2" aria-hidden="true" />}
          >
            Add Endpoint
          </AppButton>
        )}
      </div>
      <div className="card-body">
        {endpoints.length === 0 ? (
          <EmptyState
            icon="fa-plug"
            title="Add your first endpoint"
            body="An endpoint is where integrations deliver: an SMTP server and its recipients, a Slack webhook, an HTTPS webhook or a stream topic, with the credentials to reach it."
            docsHref={DOCS_URL.integrations}
          />
        ) : shown.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No endpoints match your filter.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '36%' }}>Name</th>
                  <th style={{ width: '14%' }}>Type</th>
                  <th style={{ width: '12%' }}>Status</th>
                  <th style={{ width: '20%' }}>Used by</th>
                  {(canEdit || canDelete) && <th style={{ width: '18%' }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {shown.map(endpoint => {
                  const users = usersOf(endpoint);
                  return (
                    <tr
                      key={endpoint.id}
                      onClick={canEdit ? () => navigate(endpointPath(endpoint.id)) : undefined}
                      style={canEdit ? { cursor: 'pointer' } : undefined}
                    >
                      <td>
                        <strong>{endpoint.name}</strong>
                        {endpoint.description && (
                          <div className="small text-muted">{endpoint.description}</div>
                        )}
                      </td>
                      <td>
                        <span className="badge text-bg-secondary">{endpoint.type}</span>
                      </td>
                      <td>
                        <span
                          className={`badge ${endpoint.status === 'active' ? 'text-bg-success' : 'text-bg-secondary'}`}
                        >
                          {endpoint.status}
                        </span>
                      </td>
                      <td title={users.join(', ') || undefined}>{usedByLabel(users.length)}</td>
                      {(canEdit || canDelete) && (
                        <td onClick={e => e.stopPropagation()}>
                          <div className="d-flex gap-2 align-items-center">
                            {canEdit && (
                              <>
                                <AppButton
                                  variant="secondary"
                                  size="sm"
                                  onClick={() => sendTest(endpoint)}
                                  disabled={testingId === endpoint.id}
                                  title="Send a test message"
                                  aria-label={`Test endpoint ${endpoint.name}`}
                                >
                                  {testingId === endpoint.id ? (
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
                                  onClick={() => navigate(endpointPath(endpoint.id))}
                                  title="Edit"
                                  aria-label={`Edit endpoint ${endpoint.name}`}
                                >
                                  <i className="fas fa-edit" aria-hidden="true"></i>
                                </AppButton>
                              </>
                            )}
                            {canDelete && (
                              <DeleteButton
                                onDelete={() => remove(endpoint)}
                                disabled={users.length > 0}
                                title={
                                  users.length > 0
                                    ? `Used by ${users.join(', ')}`
                                    : 'Delete endpoint'
                                }
                                aria-label={`Delete endpoint ${endpoint.name}`}
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

export default EndpointsTab;
