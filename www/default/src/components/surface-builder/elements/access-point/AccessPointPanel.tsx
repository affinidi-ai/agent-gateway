import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import RouteListenerSection from '../_shared/RouteListenerSection';
import { AgentCardLocationHelp, AGENT_CARD_EXPLAINER } from '../_shared/AgentCardLocationHelp';
import FieldHelp from '../../../shared/FieldHelp';

const AccessPointPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  allNodes,
  replaceCommit,
  hasAttemptedSave,
}) => {
  const isA2aLike = protocol === 'a2a' || protocol === 'ap2';

  return (
    <>
      <RouteListenerSection
        config={config}
        updateField={updateField}
        updateFields={updateFields}
        addressSource="inbound"
        routeFieldName="route"
        bannerLabel="Channel Route"
        replaceCommit={replaceCommit}
        hasAttemptedSave={hasAttemptedSave}
      />

      {isA2aLike && (
        <div className="config-section">
          <label>A2A Extensions</label>
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Primary extension URI</Form.Label>
              <FieldHelp
                testId="field-help-access-point-primary-extension-uri"
                ariaLabel="About Primary extension URI"
              >
                If your agent supports an official add-on capability for the A2A (Agent2Agent)
                protocol, an "extension," enter its identifying web address here. It doesn't need to
                be a working link, just the extension's published identifier. Leave blank if not
                applicable.
              </FieldHelp>
            </div>
            <Form.Control
              size="sm"
              type="text"
              placeholder="https://ucp.dev/specification/reference?v=2026-01-11"
              value={config.primary_extension || ''}
              onChange={e => updateField('primary_extension', e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">
                Supported extensions (comma-separated)
              </Form.Label>
              <FieldHelp
                testId="field-help-access-point-supported-extensions"
                ariaLabel="About Supported extensions"
              >
                List every optional A2A (Agent2Agent) protocol extension your agent supports,
                separated by commas (e.g. <code>https://ext-a, https://ext-b</code>).
              </FieldHelp>
            </div>
            <Form.Control
              as="textarea"
              rows={2}
              size="sm"
              placeholder="https://ext-a, https://ext-b"
              value={
                Array.isArray(config.supported_extensions)
                  ? config.supported_extensions.join(', ')
                  : config.supported_extensions || ''
              }
              onChange={e => updateField('supported_extensions', e.target.value)}
            />
          </Form.Group>
        </div>
      )}

      {isA2aLike && (
        <div className="config-section">
          <label>Agent Card</label>{' '}
          <Form.Check
            type="checkbox"
            id="ap-override-agent-card"
            label={
              <span className="d-flex align-items-center gap-1">
                Override Agent Card Location
                <FieldHelp
                  testId="field-help-access-point-override-agent-card-location"
                  ariaLabel="About Override Agent Card Location"
                >
                  {AGENT_CARD_EXPLAINER} By default, the gateway serves this agent's card from the
                  configured endpoint plus <code>/.well-known/agent-card.json</code>. Enable this to
                  serve it from a custom path instead. If the path is wrong, other systems
                  requesting your agent's card here will get an error.
                </FieldHelp>
              </span>
            }
            checked={!!config.override_agent_card_location}
            onChange={e => {
              const enabled = e.target.checked;
              updateFields({
                override_agent_card_location: enabled,
                agent_card_path: enabled
                  ? config.agent_card_path || '.well-known/agent-card.json'
                  : '',
              });
            }}
          />
          {config.override_agent_card_location && (
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Agent Card Location</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder=".well-known/agent-card.json"
                value={config.agent_card_path || ''}
                onChange={e => updateField('agent_card_path', e.target.value)}
              />
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                <AgentCardLocationHelp
                  endpoint={
                    allNodes?.find(n => n.type === 'target')?.config?.endpoint as string | undefined
                  }
                  customPath={config.agent_card_path}
                />
              </Form.Text>
            </Form.Group>
          )}
        </div>
      )}
    </>
  );
};

export default AccessPointPanel;
