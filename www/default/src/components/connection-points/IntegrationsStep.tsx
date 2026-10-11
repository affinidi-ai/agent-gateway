import React, { useEffect, useState } from 'react';
import { IntegrationPreview } from '../integrations/IntegrationPreview';
import FieldHelp from '../shared/FieldHelp';
import { extractAllTemplateVariables, type TemplateVariable } from '../../utils/templateVariables';

export interface integrationIntegration {
  integration_id: string;
  variables: Record<string, string>;
  event_types?: string[]; // Optional: filter which events trigger this integration
}

interface IntegrationsStepProps {
  integrations: integrationIntegration[];
  onChange: (integrations: integrationIntegration[]) => void;
  availableIntegrations: Array<{
    id: string;
    name: string;
    type: string;
    content?: any;
    category?: string;
    tenant_id?: string | null;
  }>;
  runtimeVariables?: Record<string, { label: string; example: string }>;
  onValidationChange?: (hasErrors: boolean) => void;
  /** Category determines which runtime variables are available (general, connection_point, user, gateway, surface) */
  category?: string;
  /** Available event types for filtering (only for user category) */
  availableEventTypes?: Array<{ value: string; label: string; description: string }>;
  /** Render the integration selector flush (no wrapping card) when the parent already provides one */
  bareSelector?: boolean;
  /** Every attached integration must name at least one of `availableEventTypes` */
  requireEventTypes?: boolean;
  /**
   * The events describe the whole appliance (user, identity), so only categorised integrations
   * without a tenant owner can receive them, as the gateway enforces
   */
  applianceWide?: boolean;
}

/**
 * Reusable integrations step for managing multiple integration integrations
 * Allows users to select integrations, configure variables, and preview templates
 */
export const IntegrationsStep: React.FC<IntegrationsStepProps> = ({
  integrations,
  onChange,
  availableIntegrations,
  runtimeVariables = {},
  onValidationChange,
  category,
  availableEventTypes = [],
  bareSelector = false,
  requireEventTypes = false,
  applianceWide = false,
}) => {
  const [expandedIntegrations, setExpandedIntegrations] = useState<Set<number>>(new Set());

  // An integration of this category or 'general' can be attached. An uncategorised one only on
  // resource pages (backward compatibility), and a tenant-owned one never to appliance-wide events.
  const isAttachable = (integration: IntegrationsStepProps['availableIntegrations'][number]) => {
    if (applianceWide && integration.tenant_id) return false;
    if (!integration.category) return !applianceWide;
    return integration.category === 'general' || integration.category === category;
  };

  const filteredIntegrations = availableIntegrations.filter(
    integration =>
      !integrations.some(attached => attached.integration_id === integration.id) &&
      isAttachable(integration)
  );

  // Get all variables from a integration's template
  const getIntegrationTemplateVariables = (integration: any): TemplateVariable[] => {
    if (!integration?.content) {
      return [];
    }

    let templateText = '';

    if (integration.type === 'email') {
      const subject = integration.content.subject || '';
      const body = integration.content.body || '';
      templateText = `${subject}\n${body}`;
    } else if (integration.type === 'slack') {
      templateText = integration.content.text || '';
    } else {
      templateText = JSON.stringify(integration.content);
    }

    const variables = extractAllTemplateVariables(templateText);
    return variables;
  };

  // Custom variables (starting with _) need an operator-supplied value; runtime ones are filled in
  const getCustomVariableNames = (integration: any): string[] =>
    getIntegrationTemplateVariables(integration)
      .map(variable => variable.name)
      .filter(name => name.startsWith('_'));

  const toggleIntegration = (index: number) => {
    const newExpanded = new Set(expandedIntegrations);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedIntegrations(newExpanded);
  };

  const handleRemoveIntegration = (index: number) => {
    const updated = integrations.filter((_, i) => i !== index);
    setExpandedIntegrations(
      new Set(
        Array.from(expandedIntegrations)
          .filter(open => open !== index)
          .map(open => (open > index ? open - 1 : open))
      )
    );
    onChange(updated);
  };

  const handleVariableChange = (index: number, key: string, value: string) => {
    const updated = [...integrations];
    updated[index].variables = {
      ...updated[index].variables,
      [key]: value,
    };
    onChange(updated);
  };

  const getIntegrationById = (id: string) => {
    return availableIntegrations.find(n => n.id === id);
  };

  const handleAttachIntegration = (integrationId: string) => {
    const integration = getIntegrationById(integrationId);
    if (!integration) return;
    const variables = Object.fromEntries(
      getCustomVariableNames(integration).map(name => [name, ''])
    );
    setExpandedIntegrations(new Set(expandedIntegrations).add(integrations.length));
    onChange([...integrations, { integration_id: integrationId, variables, event_types: [] }]);
  };

  // A stored mapping whose integration is gone or no longer attachable: shown so it can be removed
  const isUnavailable = (integration: integrationIntegration) => {
    const config = getIntegrationById(integration.integration_id);
    return !config || !isAttachable(config);
  };
  const attachable = integrations.filter(integration => !isUnavailable(integration));

  const hasUnavailable = attachable.length < integrations.length;
  const hasMissingVariables = attachable.some(integration => {
    const config = getIntegrationById(integration.integration_id);
    return getCustomVariableNames(config).some(name => !integration.variables[name]?.trim());
  });
  const hasMissingEventTypes =
    requireEventTypes &&
    availableEventTypes.length > 0 &&
    attachable.some(integration => (integration.event_types ?? []).length === 0);
  const hasValidationErrors = hasUnavailable || hasMissingVariables || hasMissingEventTypes;

  useEffect(() => {
    onValidationChange?.(hasValidationErrors);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasValidationErrors]);

  const getPreviewTemplate = (integration: any): string => {
    if (!integration?.content) return 'No template configured';

    // For email integrations, concatenate subject and body
    if (integration.type === 'email') {
      const subject = integration.content.subject || '';
      const body = integration.content.body || '';
      return `Subject: ${subject}\n\n${body}`;
    }

    // For slack integrations, use text
    if (integration.type === 'slack') {
      return integration.content.text || '';
    }

    return JSON.stringify(integration.content, null, 2);
  };

  const getMergedVariables = (integration: integrationIntegration): Record<string, string> => {
    const runtimeVarExamples: Record<string, string> = {};
    Object.entries(runtimeVariables).forEach(([key, value]) => {
      runtimeVarExamples[key] = value.example;
    });
    return {
      ...runtimeVarExamples,
      ...integration.variables,
    };
  };

  return (
    <>
      {hasUnavailable && (
        <div className="alert alert-warning mb-4">
          <i className="fas fa-exclamation-triangle me-1"></i>
          Some integrations can no longer be attached here. Remove the integrations marked NOT
          AVAILABLE before saving.
        </div>
      )}
      {hasMissingVariables && (
        <div className="alert alert-warning mb-4">
          <i className="fas fa-exclamation-triangle me-1"></i>
          Some variables have empty values. Please fill in all variable values before saving.
        </div>
      )}
      {hasMissingEventTypes && (
        <div className="alert alert-warning mb-4">
          <i className="fas fa-exclamation-triangle me-1"></i>
          Select at least one event for each integration.
        </div>
      )}

      {/* Add New Integration */}
      {(() => {
        const selectorField = (
          <div className="row align-items-center">
            <div className="col-md-12">
              <label>Select Integration (optional)</label>
              <select
                className="form-control dropdown-styling"
                value=""
                onChange={e => handleAttachIntegration(e.target.value)}
                disabled={filteredIntegrations.length === 0}
                title="Select an integration to add"
                data-testid="integrations-step-select"
              >
                <option value="">Select an integration</option>
                {filteredIntegrations.map(integration => (
                  <option key={integration.id} value={integration.id}>
                    {integration.name} ({integration.type})
                  </option>
                ))}
              </select>
            </div>
          </div>
        );

        if (bareSelector) {
          return <div className="mb-4">{selectorField}</div>;
        }

        return (
          <div className="card shadow-sm mb-4">
            <div className="card-body">{selectorField}</div>
          </div>
        );
      })()}

      {/* Integrations List */}
      {integrations.map((integration, index) => {
        const integrationConfig = getIntegrationById(integration.integration_id);
        if (!integrationConfig || isUnavailable(integration)) {
          return (
            <div
              key={index}
              className="card mb-2 border-warning"
              data-testid={`integration-${index}-unavailable`}
            >
              <div className="card-body py-2 px-3 d-flex justify-content-between align-items-center">
                <div className="d-flex align-items-center">
                  {integrationConfig && (
                    <span className="font-weight-bold me-2">{integrationConfig.name}</span>
                  )}
                  <code>{integration.integration_id}</code>
                  <span className="badge text-bg-warning ms-2">NOT AVAILABLE</span>
                </div>
                <button
                  className="btn btn-sm btn-outline-danger"
                  onClick={() => handleRemoveIntegration(index)}
                  title="Remove integration"
                >
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </div>
          );
        }
        const isExpanded = expandedIntegrations.has(index);
        // Get variable metadata for labels - this dynamically extracts from current template
        const variableMetadata = getIntegrationTemplateVariables(integrationConfig);

        // Dynamically get current variables from template
        const currentTemplateVars = variableMetadata.reduce(
          (acc, varInfo) => {
            acc[varInfo.name] = integration.variables[varInfo.name] || '';
            return acc;
          },
          {} as Record<string, string>
        );

        // Use currentTemplateVars for display instead of integration.variables
        const displayVariables = currentTemplateVars;

        // Check if this integration has validation errors (only for custom variables)
        const customVars = Object.entries(displayVariables).filter(([key]) => key.startsWith('_'));
        const hasErrors =
          customVars.length > 0 && customVars.some(([_, value]) => !value || value.trim() === '');

        return (
          <div key={index} className="card mb-2">
            <div
              className="card-body py-2 px-3 cursor-pointer"
              onClick={() => toggleIntegration(index)}
            >
              {/* Collapsed Header */}
              <div className="d-flex justify-content-between align-items-center">
                <div className="d-flex align-items-center">
                  <i
                    className={`fas fa-chevron-${isExpanded ? 'down' : 'right'} me-2 text-muted`}
                  ></i>
                  <span className="font-weight-bold">{integrationConfig.name}</span>
                  <span className="badge text-bg-primary ms-2">
                    {integrationConfig.type.toUpperCase()}
                  </span>
                  {Object.keys(displayVariables).length > 0 && (
                    <span className="badge text-bg-secondary ms-2">
                      {Object.keys(displayVariables).length} VARIABLE
                      {Object.keys(displayVariables).length !== 1 ? 'S' : ''}
                    </span>
                  )}
                  {hasErrors && (
                    <span className="badge text-bg-danger ms-2">
                      <i className="fas fa-exclamation-triangle me-1"></i>MISSING DATA
                    </span>
                  )}
                </div>
                <button
                  className="btn btn-sm btn-outline-danger"
                  onClick={e => {
                    e.stopPropagation();
                    handleRemoveIntegration(index);
                  }}
                  title="Remove integration"
                >
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </div>

            {/* Expanded Content */}
            {isExpanded && (
              <div className="card-body border-top" onClick={e => e.stopPropagation()}>
                <div className="row">
                  {/* Main Content */}
                  <div className="col-md-12">
                    {/* Event Type Filter (only for user category) */}
                    {availableEventTypes.length > 0 && (
                      <div className="mb-3">
                        <h6>
                          <i className="fas fa-filter me-2"></i>
                          Trigger Events
                        </h6>
                        <p className="text-muted small">
                          {requireEventTypes
                            ? 'Select at least one event to trigger this integration.'
                            : 'Select which events should trigger this integration. If none are selected, all events will trigger this integration.'}
                        </p>
                        <div className="row">
                          {availableEventTypes.map(eventType => (
                            <div key={eventType.value} className="col-md-6 mb-2">
                              <div className="custom-control custom-checkbox">
                                <input
                                  type="checkbox"
                                  className="custom-control-input"
                                  id={`event-${index}-${eventType.value}`}
                                  data-testid={`integration-${index}-event-${eventType.value}`}
                                  checked={
                                    integration.event_types?.includes(eventType.value) || false
                                  }
                                  onChange={e => {
                                    const currentEventTypes = integration.event_types || [];
                                    const newEventTypes = e.target.checked
                                      ? [...currentEventTypes, eventType.value]
                                      : currentEventTypes.filter(et => et !== eventType.value);
                                    const newIntegrations = [...integrations];
                                    newIntegrations[index] = {
                                      ...integration,
                                      event_types: newEventTypes,
                                    };
                                    onChange(newIntegrations);
                                  }}
                                />
                                <label
                                  className="custom-control-label"
                                  htmlFor={`event-${index}-${eventType.value}`}
                                >
                                  <strong>{eventType.label}</strong>
                                  <br />
                                  <small className="text-muted">{eventType.description}</small>
                                </label>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Template Variables */}
                    <div className="mb-3">
                      <h6>
                        Template Variables{' '}
                        <FieldHelp
                          testId="field-help-integration-custom-variables"
                          ariaLabel="About custom variables"
                        >
                          The leading underscore keeps a custom variable from ever colliding with
                          one of the system's own runtime variables.
                        </FieldHelp>
                      </h6>
                      <p className="text-muted small">
                        <strong>Custom variables</strong> (starting with _) require you to provide
                        values. <strong>Runtime variables</strong> are automatically filled by the
                        system at execution time.
                      </p>

                      {Object.keys(displayVariables).filter(k => k.startsWith('_')).length === 0 ? (
                        <div className="alert alert-info">
                          <i className="fas fa-info-circle me-1"></i>
                          No custom variables are defined in this template. Runtime variables will
                          be automatically populated.
                        </div>
                      ) : (
                        Object.entries(displayVariables)
                          .filter(([key]) => key.startsWith('_')) // Only show custom variables for user input
                          .map(([key, value]) => {
                            const varInfo = variableMetadata.find(v => v.name === key);
                            return (
                              <VariableRow
                                key={key}
                                variableName={key}
                                variableLabel={varInfo?.label}
                                value={value}
                                runtimeVariables={runtimeVariables}
                                onChange={newValue => handleVariableChange(index, key, newValue)}
                              />
                            );
                          })
                      )}
                    </div>

                    {/* Preview */}
                    <IntegrationPreview
                      label="Template Preview"
                      template={getPreviewTemplate(integrationConfig)}
                      variables={getMergedVariables(integration)}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </>
  );
};

// Helper component for a single variable row with literal/runtime variable selection
const VariableRow: React.FC<{
  variableName: string;
  variableLabel?: string;
  value: string;
  runtimeVariables: Record<string, { label: string; example: string }>;
  onChange: (value: string) => void;
}> = ({ variableName, variableLabel, value, runtimeVariables, onChange }) => {
  const hasError = !value || value.trim() === '';

  return (
    <div className="row mb-2 align-items-center">
      <div className="col-auto" style={{ minWidth: '120px' }}>
        {variableLabel ? (
          <div>
            <label className="mb-0 font-weight-bold">{variableLabel}</label>
            <div className="text-muted small">
              <code>
                {'${'}
                {variableName}
                {'}'}
              </code>
            </div>
          </div>
        ) : (
          <label className="mb-0 font-weight-bold text-monospace">
            {'${'}
            {variableName}
            {'}'}
          </label>
        )}
      </div>
      <div className="col-8">
        <input
          type="text"
          className={`form-control form-control-sm ${hasError ? 'is-invalid' : ''}`}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder="Enter literal value for custom variable..."
        />
        <small className="form-text text-muted">
          Custom variable - runtime variables are automatically populated
        </small>
      </div>
    </div>
  );
};
