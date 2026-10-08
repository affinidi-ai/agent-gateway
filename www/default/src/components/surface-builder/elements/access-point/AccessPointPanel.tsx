import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import RouteListenerSection from '../_shared/RouteListenerSection';
import { AgentCardLocationHelp, AGENT_CARD_EXPLAINER } from '../_shared/AgentCardLocationHelp';
import FieldHelp from '../../../shared/FieldHelp';
import {
  A2A_PROXY_SETTINGS,
  A2A_VERSIONS,
  isA2aProxyEndpoint,
  selectedA2aVersions,
} from './a2aSettings';

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
  const targetEndpoint = allNodes?.find(n => n.type === 'target')?.config?.endpoint;
  // An A2A proxy Target serves A2A 1.0 without message validation, whatever
  // was selected, so the controls show those values and are locked.
  const isA2aProxyTarget = isA2aProxyEndpoint(targetEndpoint);
  const a2aVersions = isA2aProxyTarget
    ? A2A_PROXY_SETTINGS.accepted_versions
    : selectedA2aVersions(config);
  const a2aValidateMessages = isA2aProxyTarget
    ? A2A_PROXY_SETTINGS.validate_messages
    : config.a2a_validate_messages === true;

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

      {protocol === 'a2a' && (
        <div className="config-section" data-testid="access-point-a2a-protocol">
          <label>A2A Protocol</label>
          {isA2aProxyTarget && (
            <Form.Text
              className="text-muted d-block mb-1"
              style={{ fontSize: '10px' }}
              data-testid="access-point-a2a-proxy-locked"
            >
              An A2A proxy target serves A2A 1.0 without message validation.
            </Form.Text>
          )}
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Supported versions</Form.Label>
              <FieldHelp
                testId="field-help-access-point-a2a-versions"
                ariaLabel="About Supported versions"
              >
                The A2A (Agent2Agent) protocol versions callers may use with this surface. A caller
                declares its version in the <code>A2A-Version</code> header, and a request without
                that header counts as version 0.3. A request for a version that is not selected is
                refused with an unsupported-version error that lists the selected versions.
              </FieldHelp>
            </div>
            <div className="d-flex gap-3">
              {A2A_VERSIONS.map(version => (
                <Form.Check
                  key={version}
                  type="checkbox"
                  id={`ap-a2a-version-${version}`}
                  data-testid={`access-point-a2a-version-${version}`}
                  label={`A2A ${version}`}
                  checked={a2aVersions.includes(version)}
                  disabled={isA2aProxyTarget}
                  onChange={e => {
                    const next = e.target.checked
                      ? [...a2aVersions, version]
                      : a2aVersions.filter(v => v !== version);
                    updateFields({
                      a2a_accepted_versions: A2A_VERSIONS.filter(v => next.includes(v)),
                    });
                  }}
                />
              ))}
            </div>
            {!isA2aProxyTarget && a2aVersions.length === 0 && (
              <Form.Text
                className="text-danger d-block"
                style={{ fontSize: '10px' }}
                data-testid="access-point-a2a-versions-error"
              >
                Select at least one supported A2A version.
              </Form.Text>
            )}
          </Form.Group>
          <Form.Check
            type="checkbox"
            id="ap-a2a-validate-messages"
            data-testid="access-point-a2a-validate-messages"
            label={
              <span className="d-flex align-items-center gap-1">
                Validate messages
                <FieldHelp
                  testId="field-help-access-point-a2a-validate-messages"
                  ariaLabel="About Validate messages"
                >
                  Check each request before it reaches your agent: that it is a well-formed JSON-RPC
                  request carrying the fields A2A requires, such as a message ID, a role and at
                  least one message part. A malformed request is refused with an error that names
                  the field. When this is off, requests are forwarded as they are and your agent
                  decides.
                </FieldHelp>
              </span>
            }
            checked={a2aValidateMessages}
            disabled={isA2aProxyTarget}
            onChange={e => updateFields({ a2a_validate_messages: e.target.checked })}
          />
        </div>
      )}

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
                  endpoint={targetEndpoint as string | undefined}
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
