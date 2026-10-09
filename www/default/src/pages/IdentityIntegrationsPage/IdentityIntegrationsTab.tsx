import React, { useEffect, useState } from 'react';
import {
  IntegrationsStep,
  integrationIntegration,
} from '../../components/connection-points/IntegrationsStep';
import { apiClient } from '../../api';
import { getRuntimeVariablesForCategories } from '../../utils/runtimeVariables';

interface Integration {
  id: string;
  name: string;
  type: string;
  content?: any;
}

interface IdentityIntegrationsTabProps {
  integrations: integrationIntegration[];
  onIntegrationsChange: (integrations: integrationIntegration[]) => void;
  onValidationChange?: (hasErrors: boolean) => void;
}

const IdentityIntegrationsTab: React.FC<IdentityIntegrationsTabProps> = ({
  integrations,
  onIntegrationsChange,
  onValidationChange,
}) => {
  const [availableIntegrations, setAvailableIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runtimeVariables, setRuntimeVariables] = useState<
    Record<string, { label: string; example: string; description?: string }>
  >({});
  const [showOverview, setShowOverview] = useState(false);
  const [availableEventTypes, setAvailableEventTypes] = useState<
    Array<{ value: string; label: string; description: string }>
  >([]);

  useEffect(() => {
    fetchIntegrations();
    fetchRuntimeVars();
    fetchEventTypes();
  }, []);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/integrations');
      setAvailableIntegrations(response.data);
    } catch (error: any) {
      setError(error.message || 'Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const fetchRuntimeVars = async () => {
    try {
      const vars = await getRuntimeVariablesForCategories(['general', 'identity']);
      setRuntimeVariables(vars);
    } catch (error) {
      console.error('Failed to load runtime variables:', error);
    }
  };

  const fetchEventTypes = async () => {
    try {
      const response = await apiClient.get('/integrations/config');
      const config = response.data;

      // Find the identity category
      const identityCategory = config.categories?.find((cat: any) => cat.enum_value === 'identity');

      // Extract event types from the identity category metadata
      if (identityCategory?.metadata?.event_types) {
        const eventTypes = identityCategory.metadata.event_types.map((event: any) => ({
          value: event.event_type,
          label: event.name,
          description: event.description,
        }));
        setAvailableEventTypes(eventTypes);
      }
    } catch (error) {
      console.error('Failed to load event types:', error);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border" role="status">
          <span className="visually-hidden"></span>
        </div>
        <p className="mt-2">Loading notifiers...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger">
        <i className="fas fa-exclamation-triangle me-2"></i>
        {error}
      </div>
    );
  }

  return (
    <div>
      {/* Collapsible Overview Section */}
      <div className="card shadow mb-4">
        <div
          className="card-header py-3 cursor-pointer"
          onClick={() => setShowOverview(!showOverview)}
          style={{ cursor: 'pointer' }}
        >
          <h6 className="m-0 font-weight-bold text-primary">
            <i className={`fas fa-chevron-${showOverview ? 'down' : 'right'} me-2`}></i>
            <i className="fas fa-info-circle me-2"></i>
            About Identity Integrations
          </h6>
        </div>
        {showOverview && (
          <div className="card-body">
            <p className="mb-3">
              Configure notifiers that will be triggered for identity management events. These
              integrations allow you to connect external systems and services to be notified when
              identity-related actions occur.
            </p>

            <h6 className="font-weight-bold mt-4 mb-2">Supported Events:</h6>
            <ul className="mb-3">
              <li>
                <strong>Identity Created (identity.created):</strong> Triggered when a new DID is
                created for an agent identity
              </li>
              <li>
                <strong>Identity Used (identity.used):</strong> Triggered when an identity is used
                for authentication or signing
              </li>
              <li>
                <strong>Identity Updated (identity.updated):</strong> Triggered when identity
                details are modified
              </li>
              <li>
                <strong>Identity Deleted (identity.deleted):</strong> Triggered when an identity is
                permanently deleted
              </li>
            </ul>

            <div className="alert alert-warning">
              <i className="fas fa-info-circle me-2"></i>
              <strong>Notifier Triggers:</strong> Identity notifiers are automatically invoked for
              the above events. Ensure your notifiers are configured with the{' '}
              <strong>"identity"</strong> or <strong>"general"</strong> category to receive these
              events.
            </div>

            <h6 className="font-weight-bold mt-4 mb-2">Available Runtime Variables:</h6>
            {loading ? (
              <div className="text-center py-3">
                <i className="fas fa-spinner fa-spin"></i> Loading variables...
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-sm table-bordered">
                  <thead>
                    <tr>
                      <th>Variable</th>
                      <th>Description</th>
                      <th>Example</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(runtimeVariables).length > 0 ? (
                      Object.entries(runtimeVariables).map(([key, info]) => (
                        <tr key={key}>
                          <td>
                            <code>${key}</code>
                          </td>
                          <td>{info.description || info.label}</td>
                          <td>
                            <code>{info.example}</code>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={3} className="text-center text-muted">
                          No runtime variables available
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            <h6 className="font-weight-bold mt-4 mb-2">Event Filtering:</h6>
            <p className="mb-2">
              You can optionally filter which events trigger each notifier by selecting specific
              event types. If no event types are selected, the notifier will be triggered for all
              identity events.
            </p>
          </div>
        )}
      </div>

      {/* Integrations Configuration */}
      <IntegrationsStep
        integrations={integrations}
        onChange={onIntegrationsChange}
        availableIntegrations={availableIntegrations}
        runtimeVariables={runtimeVariables}
        onValidationChange={onValidationChange}
        category="identity"
        availableEventTypes={availableEventTypes}
        requireEventTypes
      />
    </div>
  );
};

export default IdentityIntegrationsTab;
