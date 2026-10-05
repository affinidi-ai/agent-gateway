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

interface GatewayIntegrationsTabProps {
  integrations: integrationIntegration[];
  onIntegrationsChange: (integrations: integrationIntegration[]) => void;
  onValidationChange?: (hasErrors: boolean) => void;
  onSave?: () => void;
  isModified?: boolean;
  isSaving?: boolean;
}

const GatewayIntegrationsTab: React.FC<GatewayIntegrationsTabProps> = ({
  integrations,
  onIntegrationsChange,
  onValidationChange,
  onSave,
  isModified = false,
  isSaving = false,
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
      const vars = await getRuntimeVariablesForCategories(['general', 'gateway']);
      setRuntimeVariables(vars);
    } catch (error) {
      console.error('Failed to load runtime variables:', error);
    }
  };

  const fetchEventTypes = async () => {
    try {
      const response = await apiClient.get('/integrations/config');
      const config = response.data;

      // Find the gateway category
      const gatewayCategory = config.categories?.find((cat: any) => cat.enum_value === 'gateway');

      // Extract event types from the gateway category metadata
      if (gatewayCategory?.metadata?.event_types) {
        const eventTypes = gatewayCategory.metadata.event_types.map((event: any) => ({
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
        <p className="mt-2">Loading integrations...</p>
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
    <>
      {/* Collapsible Overview Section */}
      <div className="card shadow-sm mb-4">
        <div
          className="card-header py-3 cursor-pointer"
          onClick={() => setShowOverview(!showOverview)}
          style={{ cursor: 'pointer' }}
        >
          <h6 className="m-0 font-weight-bold text-primary">
            <i className={`fas fa-chevron-${showOverview ? 'down' : 'right'} me-2`}></i>
            <i className="fas fa-info-circle me-2"></i>
            About Gateway Integrations
          </h6>
        </div>
        {showOverview && (
          <div className="card-body">
            <p className="mb-3">
              Configure integrations that will be triggered for gateway management events. These
              integrations allow you to connect external systems and services to be notified when
              gateway-related actions occur.
            </p>

            <h6 className="font-weight-bold mt-4 mb-2">Supported Events:</h6>
            <ul className="mb-3">
              {availableEventTypes.length > 0 ? (
                availableEventTypes.map(event => (
                  <li key={event.value}>
                    <strong>
                      {event.label} ({event.value}):
                    </strong>{' '}
                    {event.description}
                  </li>
                ))
              ) : (
                <li className="text-muted">Loading event types...</li>
              )}
            </ul>

            <div className="alert alert-warning">
              <i className="fas fa-info-circle me-2"></i>
              <strong>Integration Triggers:</strong> Gateway integrations are automatically invoked
              for the above events. Ensure your integrations are configured with the{' '}
              <strong>"gateway"</strong> or <strong>"general"</strong> category to receive these
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
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(runtimeVariables).map(([name, info]) => (
                      <tr key={name}>
                        <td>
                          <code>{`\${${name}}`}</code>
                        </td>
                        <td>{info.description}</td>
                      </tr>
                    ))}
                    {Object.keys(runtimeVariables).length === 0 && (
                      <tr>
                        <td colSpan={2} className="text-center text-muted">
                          No variables available
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            <div className="alert alert-info mt-4">
              <i className="fas fa-lightbulb me-2"></i>
              <strong>Tip:</strong> Configure integrations below and map runtime variables to their
              templates. These variables will be automatically populated when events occur.
            </div>
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
        category="gateway"
        availableEventTypes={availableEventTypes}
      />

      {/* Save Button */}
      {onSave && (
        <div className="mt-4 pt-3 border-top d-flex justify-content-end">
          <button
            className={`btn btn-primary ${isSaving ? 'disabled' : ''}`}
            onClick={onSave}
            disabled={!isModified || isSaving}
          >
            {isSaving ? (
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
                <i className="fas fa-save me-2"></i>
                Save Integrations
              </>
            )}
          </button>
        </div>
      )}
    </>
  );
};

export default GatewayIntegrationsTab;
