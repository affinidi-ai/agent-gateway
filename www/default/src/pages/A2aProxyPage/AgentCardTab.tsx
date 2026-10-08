import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../components/shared/FieldHelp';
import InfoBanner from '../../components/shared/InfoBanner';
import { DOCS_URL } from '../../config/docs';
import type { A2aProxyFormData } from './types';

interface AgentCardTabProps {
  formData: A2aProxyFormData;
  onChange: (patch: Partial<A2aProxyFormData>) => void;
}

const AgentCardTab: React.FC<AgentCardTabProps> = ({ formData, onChange }) => {
  const isCopilotDirectLine = formData.backend.kind === 'copilot_direct_line';

  return (
    <div data-testid="a2a-proxy-agent-card-tab">
      <InfoBanner
        title="What is an agent card?"
        testIdPrefix="a2a-proxy-agent-card-intro"
        docLink={DOCS_URL.proxies}
      >
        <p>
          Some backends (like this one) don&apos;t publish their own agent card, a small public
          profile describing what an agent can do. This proxy generates one automatically.
        </p>
        <p data-testid="a2a-proxy-agent-card-version">
          The generated card uses A2A version 1.0 only, and the proxy answers in A2A 1.0: an Agent
          Surface that targets this proxy accepts A2A 1.0 callers only.
        </p>
        <p className="mb-0">
          Leave the fields below blank to reuse the name and description of the Agent Surface that
          exposes this proxy.
        </p>
      </InfoBanner>

      <div className="row">
        <div className="col-lg-6">
          <Form.Group className="mb-3">
            <Form.Label>
              Card name override{' '}
              <FieldHelp
                testId="field-help-a2a-agent-card-name"
                ariaLabel="About Card name override"
              >
                Overrides the name shown in this proxy&apos;s public agent card.
              </FieldHelp>
            </Form.Label>
            <Form.Control
              data-testid="a2a-proxy-agent-card-name-input"
              value={formData.agent_card_name}
              onChange={e => onChange({ agent_card_name: e.target.value })}
              placeholder="Defaults to the exposing surface name"
            />
            <Form.Text className="text-muted">
              Leave blank to reuse the name of the Agent Surface this proxy exposes, most users can
              leave this blank.
            </Form.Text>
          </Form.Group>
        </div>
        <div className="col-lg-6">
          <Form.Group className="mb-3">
            <Form.Label>
              Card description override{' '}
              <FieldHelp
                testId="field-help-a2a-agent-card-description"
                ariaLabel="About Card description override"
              >
                Overrides the description shown in this proxy&apos;s public agent card.
              </FieldHelp>
            </Form.Label>
            <Form.Control
              data-testid="a2a-proxy-agent-card-description-input"
              value={formData.agent_card_description}
              onChange={e => onChange({ agent_card_description: e.target.value })}
              placeholder="Defaults to the exposing surface description"
            />
            <Form.Text className="text-muted">
              Leave blank to reuse the Agent Surface&apos;s description.
            </Form.Text>
          </Form.Group>
        </div>
      </div>

      <div className="card border-left-info shadow-sm mb-3" data-testid="a2a-proxy-identity-card">
        <div className="card-body">
          <div className="d-flex align-items-start justify-content-between gap-3 mb-3">
            <div>
              <h6 className="font-weight-bold text-primary mb-1">
                Verifiable identity{' '}
                <FieldHelp
                  testId="field-help-a2a-agent-card-identity-intro"
                  ariaLabel="About Verifiable identity"
                >
                  DID (a decentralized identifier, a portable, cryptographically verifiable ID) that
                  this proxy publishes in its agent card, plus the identity credential that proves
                  the DID is legitimately this proxy&apos;s.
                </FieldHelp>
              </h6>
              <p className="text-muted small mb-0">
                Controls this proxy&apos;s published identity, its DID and identity credential.
              </p>
              <div className="surface-info-panel-doclink">
                <a href={DOCS_URL.identity} target="_blank" rel="noopener noreferrer">
                  Learn more <i className="fas fa-arrow-right ms-1" aria-hidden="true" />
                </a>
              </div>
            </div>
            <span className="badge text-bg-info">Agent card identity</span>
          </div>

          <Form.Group className="mb-3">
            <Form.Label>
              Identity source{' '}
              <FieldHelp
                testId="field-help-a2a-agent-card-identity-source"
                ariaLabel="About Identity source"
              >
                Microsoft Entra agent identity reuses the identity Microsoft Copilot already assigns
                your bot. Pick this if Copilot sends <code>x-ms-entra-agent-id</code>/
                <code>x-ms-client-tenant-id</code> headers you can match here. Proxy-managed subject
                derives a stable identifier for this proxy instead, based on its configuration, so
                it stays the same across restarts.
              </FieldHelp>
            </Form.Label>
            <Form.Select
              data-testid="a2a-proxy-identity-type-select"
              value={formData.agent_identity_type}
              onChange={e =>
                onChange({
                  agent_identity_type: e.target.value as A2aProxyFormData['agent_identity_type'],
                })
              }
            >
              {isCopilotDirectLine && (
                <option value="entra_agent">Microsoft Entra agent identity</option>
              )}
              <option value="proxy_subject">Proxy-managed subject</option>
            </Form.Select>
            <Form.Text className="text-muted">Choose how this proxy proves its identity.</Form.Text>
          </Form.Group>

          {formData.agent_identity_type === 'entra_agent' && isCopilotDirectLine ? (
            <>
              <div className="alert alert-info py-2 small" role="note">
                Use the same values Copilot sends: <code>x-ms-entra-agent-id</code> and{' '}
                <code>x-ms-client-tenant-id</code>.{' '}
                <FieldHelp
                  testId="field-help-a2a-agent-card-entra-alert"
                  ariaLabel="About matching Entra values"
                >
                  When these match, inbound Copilot calls and this synthesized agent card resolve to
                  the same agent DID.
                </FieldHelp>
              </div>
              <div className="row">
                <div className="col-lg-6">
                  <Form.Group className="mb-3">
                    <Form.Label>
                      Entra Agent ID <span className="text-danger">*</span>
                    </Form.Label>
                    <Form.Control
                      data-testid="a2a-proxy-entra-agent-id-input"
                      value={formData.entra_agent_id}
                      onChange={e => onChange({ entra_agent_id: e.target.value })}
                      placeholder="00000000-0000-0000-0000-000000000000"
                      required
                    />
                  </Form.Group>
                </div>
                <div className="col-lg-6">
                  <Form.Group className="mb-3">
                    <Form.Label>
                      Client Tenant ID <span className="text-danger">*</span>
                    </Form.Label>
                    <Form.Control
                      data-testid="a2a-proxy-client-tenant-id-input"
                      value={formData.client_tenant_id}
                      onChange={e => onChange({ client_tenant_id: e.target.value })}
                      placeholder="11111111-1111-1111-1111-111111111111"
                      required
                    />
                  </Form.Group>
                </div>
              </div>
            </>
          ) : (
            <Form.Group className="mb-3">
              <Form.Label>Identity subject</Form.Label>
              <Form.Control
                data-testid="a2a-proxy-identity-subject-input"
                value={formData.agent_identity_subject}
                onChange={e => onChange({ agent_identity_subject: e.target.value })}
                placeholder="managed-agent-prod"
              />
              <Form.Text className="text-muted">
                Use only when the backend has no stable external identity. Leave blank to use this
                proxy's ID. Do not use secrets, tokens, or rotating credentials.
              </Form.Text>
            </Form.Group>
          )}
        </div>
      </div>
    </div>
  );
};

export default AgentCardTab;
