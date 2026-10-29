import React, { useEffect, useState } from 'react';
import { Form, Row, Col } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { fetchRoutingConfig } from '../access-point/defaults';
import FieldHelp from '../../../shared/FieldHelp';

const TransitConfigPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => {
  // The outbound listener is a gateway-wide port (separate from the AP
  // listener). Without it set on the channel the backend registers no
  // `/outbound/*` routes and every transit point returns 404 - so this
  // is the single most important field on this panel.
  const [outboundAddrs, setOutboundAddrs] = useState<string[]>([]);
  useEffect(() => {
    fetchRoutingConfig().then(rc => {
      setOutboundAddrs(rc?.available_outbound_listen_addresses ?? []);
    });
  }, []);
  const selectedOutbound: string = config.outbound_listen_address || '';

  return (
    <>
      <div className="config-section">
        <label>Outbound Listener Address</label>
        {outboundAddrs.length > 0 ? (
          <Form.Select
            size="sm"
            value={selectedOutbound}
            onChange={e => updateField('outbound_listen_address', e.target.value || undefined)}
          >
            <option value="">-- Select an outbound listener --</option>
            {outboundAddrs.map(a => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Form.Select>
        ) : (
          <Form.Control
            size="sm"
            type="text"
            placeholder="https://gateway.example.com:9443"
            value={selectedOutbound}
            onChange={e => updateField('outbound_listen_address', e.target.value || undefined)}
          />
        )}
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Required for transit points to receive traffic. The gateway routes outbound calls at
          <code>
            {' '}
            {'<this-address>'}/outbound/{'<channel-route>'}/{'<alias>'}
          </code>
          .
        </Form.Text>
      </div>

      <div className="config-section">
        <label>Transit Token Mode</label>
        <Form.Select
          size="sm"
          value={config.transit_token_mode || 'embedded'}
          onChange={e => updateField('transit_token_mode', e.target.value)}
        >
          <option value="embedded">Embedded (signed into token, readable by the agent)</option>
          <option value="reference">Reference (server-side store)</option>
        </Form.Select>
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          How the caller context is carried to downstream gateways.
        </Form.Text>
      </div>

      <div className="config-section">
        <Form.Check
          type="switch"
          id="tc-sign-requests"
          label="Sign every outbound request"
          checked={config.sign_requests !== false}
          onChange={e => updateField('sign_requests', e.target.checked)}
        />
      </div>

      <hr />
      <div className="config-section">
        <label className="d-flex align-items-center gap-1">
          Transit Policy ID
          <FieldHelp
            testId="field-help-transit-config-transit-policy-id"
            ariaLabel="About Transit Policy ID"
          >
            <p>
              This field is saved with your surface, but the gateway does not currently evaluate it
              against any request. Nothing here is enforced yet. Use OPA Policy Definition ID below
              instead if you want a policy actually applied to outbound/transit traffic.
            </p>
          </FieldHelp>
        </label>
        <Form.Control
          size="sm"
          type="text"
          placeholder="policy-id"
          value={config.transit_policy_definition_id || ''}
          onChange={e => updateField('transit_policy_definition_id', e.target.value)}
        />
      </div>

      <div className="config-section">
        <label className="d-flex align-items-center gap-1">
          OPA Policy Definition ID
          <FieldHelp
            testId="field-help-transit-config-opa-policy-definition-id"
            ariaLabel="About OPA Policy Definition ID"
          >
            <p>
              OPA (Open Policy Agent) is a general-purpose rules engine. Enter a policy's ID here to
              have the gateway evaluate it on every outbound/transit call from this surface. The
              policy can only allow or deny the request, it can't modify it. Leave blank to skip
              this check.
            </p>
          </FieldHelp>
        </label>
        <Form.Control
          size="sm"
          type="text"
          placeholder="policy-id"
          value={config.opa_policy_definition_id || ''}
          onChange={e => updateField('opa_policy_definition_id', e.target.value)}
        />
      </div>

      <hr />
      <div className="config-section">
        <label>Outbound Rate Limit</label>
        <Row>
          <Col xs={6}>
            <Form.Control
              size="sm"
              type="number"
              min="0"
              placeholder="requests"
              value={config.rate_limit_requests ?? ''}
              onChange={e => updateField('rate_limit_requests', e.target.value)}
            />
          </Col>
          <Col xs={6}>
            <Form.Control
              size="sm"
              type="number"
              min="1"
              placeholder="window (s)"
              value={config.rate_limit_window_secs ?? ''}
              onChange={e => updateField('rate_limit_window_secs', e.target.value)}
            />
          </Col>
        </Row>
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Total across every transit point. Leave requests blank to disable.
        </Form.Text>
      </div>

      <hr />
      <div className="config-section">
        <label>Outbound Extension Validation</label>
        <Form.Check
          type="switch"
          id="tc-ext-required"
          label="Require validated extensions on outbound requests"
          checked={!!config.extension_required}
          onChange={e => updateField('extension_required', e.target.checked)}
        />
        <Form.Check
          type="switch"
          id="tc-ext-resp-required"
          className="mt-1"
          label="Require validated extensions on outbound responses"
          checked={!!config.response_extension_required}
          onChange={e => updateField('response_extension_required', e.target.checked)}
        />
      </div>

      <hr />
      <div className="config-section">
        <label>Outbound Custom Metadata</label>
        <Form.Check
          type="switch"
          id="tc-custom-meta-enabled"
          label="Inject custom metadata into outbound requests"
          checked={!!config.custom_metadata_enabled}
          onChange={e => updateField('custom_metadata_enabled', e.target.checked)}
        />
        <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '10px' }}>
          Use the Custom Metadata canvas element for the payload body; this toggle controls whether
          the gateway applies the configured metadata to transit requests.
        </Form.Text>
      </div>
    </>
  );
};

export default TransitConfigPanel;
