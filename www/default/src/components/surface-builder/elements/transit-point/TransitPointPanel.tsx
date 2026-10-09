import React, { useEffect, useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';
import TransitCredentialBindingSection, {
  transitCredentialsApiToForm,
  type TransitCredentialsForm,
} from '../_shared/TransitCredentialBindingSection';
import RouteListenerSection from '../_shared/RouteListenerSection';
import FabricDelegatedCredentialsSection, {
  fabricPeerGatewayId,
  hasOutboundCredentialBindings,
} from '../_shared/FabricDelegatedCredentialsSection';
import { AgentCardLocationHelp } from '../_shared/AgentCardLocationHelp';
import { newTransitPointId, deriveTransitPointAlias } from './factory';
import { filterSelectableGateways } from '../../../../utils/gateways';

interface Gateway {
  id: string;
  name: string;
  gateway_type: string;
  creation_type: string;
}

interface GatewayChannel {
  config_id: string;
  name: string;
  protocol: string;
}

type EndpointType = 'url' | 'gateway';

const isFabricEndpoint = (endpoint: unknown): endpoint is string =>
  typeof endpoint === 'string' && endpoint.startsWith('fabric://');

const inferEndpointType = (config: ConfigPanelProps['config']): EndpointType =>
  config.endpoint_type || (isFabricEndpoint(config.target_endpoint) ? 'gateway' : 'url');

/** Extract the transit point protocol from its node type suffix. */
export function transitPointProtocol(nodeType: string | undefined): string | null {
  if (!nodeType) return null;
  const m = nodeType.match(/^transit-point-(.+)$/);
  return m ? m[1] : null;
}

const TransitPointPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  updateFields,
  replaceCommit,
  hasAttemptedSave,
  allNodes,
}) => {
  // Mint a stable hidden id on first render so backend, metrics, and
  // task monitor have something durable to key off even before the
  // surface is first saved. Never exposed in the URL.
  useEffect(() => {
    if (!config.id) {
      updateField('id', newTransitPointId());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // One-shot hydration of the panel's auth_* form fields from the
  // backend `target_auth` shape (externally-tagged TargetAuthConfig).
  // The canvas blob keeps the form fields intact across reloads, but
  // when a surface is opened that was authored elsewhere (or by an
  // older blob version) only `target_auth` is present — derive the
  // friendly auth_type / auth_secret / etc. so the user sees their
  // configuration instead of an empty section.
  const authHydratedRef = React.useRef(false);
  useEffect(() => {
    if (authHydratedRef.current) return;
    if (config.auth_type) {
      authHydratedRef.current = true;
      return;
    }
    const ta = config.target_auth;
    if (!ta || typeof ta !== 'object') return;
    const ss =
      (ta.method && typeof ta.method === 'object' && (ta.method as any).static_secret) ||
      (ta.method === 'static_secret' ? ta : null);
    if (!ss) return;
    const headerName: string = ss.header_name || 'Authorization';
    const headerFormat: string = ss.header_format || '{value}';
    let authType: string = 'custom_header';
    if (headerFormat.startsWith('Bearer ')) authType = 'bearer';
    else if (headerName === 'X-API-Key' || headerName.toLowerCase().includes('api-key')) {
      authType = 'api_key';
    }
    authHydratedRef.current = true;
    updateFields({
      auth_type: authType,
      auth_secret: ss.secret_id || '',
      auth_header_name: headerName,
      auth_header_format: headerFormat,
      auth_fallback: ta.fallback || 'reject',
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const alias: string = useMemo(
    () => deriveTransitPointAlias(config.name, config.id),
    [config.name, config.id]
  );

  const tpProtocol = transitPointProtocol(node?.type);

  // Only A2A/AP2 destinations serve an agent card, so the location override
  // is shown for those protocols only. Protocol is encoded in the TP node
  // type (`transit-point-a2a` / `transit-point-ap2` / `transit-point-mcp`).
  const supportsAgentCard =
    node?.type === 'transit-point-a2a' || node?.type === 'transit-point-ap2';
  const overrideAgentCard = !!config.override_agent_card_location || !!config.agent_card_path;

  // ── Destination ─────────────────────────────────────────────────────────
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [gatewayChannels, setGatewayChannels] = useState<GatewayChannel[]>([]);
  const [isLoadingChannels, setIsLoadingChannels] = useState(false);
  const [endpointType, setEndpointType] = useState<EndpointType>(inferEndpointType(config));
  const [selectedGatewayId, setSelectedGatewayId] = useState<string>(config.gateway_id || '');
  const [selectedGatewayChannel, setSelectedGatewayChannel] = useState<string>(
    config.gateway_channel || ''
  );

  useEffect(() => {
    apiClient
      .get('/gateways')
      .then(res => {
        setGateways(filterSelectableGateways(res.data));
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedGatewayId || endpointType !== 'gateway') return;
    setIsLoadingChannels(true);
    apiClient
      .get(`/gateways/${selectedGatewayId}/surfaces`)
      .then(res => {
        const data = res.data;
        const channels = Array.isArray(data) ? data : data?.channels || [];
        setGatewayChannels(channels);
      })
      .catch(() => setGatewayChannels([]))
      .finally(() => setIsLoadingChannels(false));
  }, [selectedGatewayId, endpointType]);

  // HTTP transit points are protocol-agnostic pass-throughs — show all
  // remote surfaces. For typed protocols, show only matching channels.
  const compatibleChannels = useMemo(() => {
    if (!tpProtocol || tpProtocol === 'http') return gatewayChannels;
    return gatewayChannels.filter(ch => ch.protocol === tpProtocol);
  }, [gatewayChannels, tpProtocol]);

  const handleEndpointTypeChange = (newType: EndpointType) => {
    const directEndpoint = isFabricEndpoint(config.target_endpoint)
      ? ''
      : config.target_endpoint || '';

    setEndpointType(newType);
    setSelectedGatewayId('');
    setSelectedGatewayChannel('');
    setGatewayChannels([]);
    setIsLoadingChannels(false);

    if (newType === 'url') {
      updateFields({
        endpoint_type: 'url',
        target_endpoint: directEndpoint,
        gateway_id: undefined,
        gateway_channel: undefined,
        fabric_remote_channel_name: undefined,
        fabric_remote_gateway_name: undefined,
      });
      return;
    }

    updateFields({
      endpoint_type: 'gateway',
      target_endpoint: '',
      gateway_id: undefined,
      gateway_channel: undefined,
      fabric_remote_channel_name: undefined,
      fabric_remote_gateway_name: undefined,
    });
  };

  return (
    <>
      <RouteListenerSection
        config={config}
        updateField={updateField}
        updateFields={updateFields}
        addressSource="outbound"
        routeFieldName="listen_path"
        bannerLabel="Listener URL"
        replaceCommit={replaceCommit}
        hasAttemptedSave={hasAttemptedSave}
      />

      <Form.Group className="mb-3">
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Routing alias derived from the name above: <code>{alias || '—'}</code>
        </Form.Text>
      </Form.Group>

      <div className="config-section">
        <label>Destination</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">Endpoint Type</Form.Label>
          <Form.Select
            size="sm"
            value={endpointType}
            onChange={e => {
              const newType = e.target.value as EndpointType;
              handleEndpointTypeChange(newType);
            }}
          >
            <option value="url">Direct URL</option>
            <option value="gateway">via Gateway Connection</option>
          </Form.Select>
        </Form.Group>

        {endpointType === 'url' && (
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">Target Endpoint</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.target_endpoint || ''}
              onChange={e => updateField('target_endpoint', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Full URL such as https://api.example.com
            </Form.Text>
          </Form.Group>
        )}

        {endpointType === 'gateway' && (
          <>
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1">Gateway</Form.Label>
              <Form.Select
                size="sm"
                value={selectedGatewayId}
                onChange={e => {
                  const gwId = e.target.value;
                  setSelectedGatewayId(gwId);
                  setSelectedGatewayChannel('');
                  setGatewayChannels([]);
                  updateField('gateway_id', gwId);
                }}
              >
                <option value="">-- Select a Gateway --</option>
                {gateways.map(gw => (
                  <option key={gw.id} value={gw.id}>
                    {gw.name}
                  </option>
                ))}
              </Form.Select>
            </Form.Group>
            {selectedGatewayId && (
              <Form.Group className="mb-2">
                <Form.Label className="small text-muted mb-1">Agent Surface on Gateway</Form.Label>
                <Form.Select
                  size="sm"
                  value={selectedGatewayChannel}
                  onChange={e => {
                    const chId = e.target.value;
                    setSelectedGatewayChannel(chId);
                    const ch = gatewayChannels.find(c => c.config_id === chId);
                    const gw = gateways.find(g => g.id === selectedGatewayId);
                    // Auto-populate the synth chain display names from
                    // the real gateway/channel names so the canvas
                    // reads sensibly straight away. Existing user
                    // overrides are preserved.
                    const patch: Record<string, any> = {
                      gateway_channel: chId,
                      target_endpoint: `fabric://${selectedGatewayId}/${chId}`,
                    };
                    if (!config.fabric_remote_channel_name && ch?.name) {
                      patch.fabric_remote_channel_name = ch.name;
                    }
                    if (!config.fabric_remote_gateway_name && gw?.name) {
                      patch.fabric_remote_gateway_name = gw.name;
                    }
                    updateFields(patch);
                  }}
                  disabled={isLoadingChannels || compatibleChannels.length === 0}
                >
                  <option value="">
                    {isLoadingChannels
                      ? '-- Loading Agent Surfaces... --'
                      : '-- Select an Agent Surface --'}
                  </option>
                  {compatibleChannels.map(ch => (
                    <option key={ch.config_id} value={ch.config_id}>
                      {ch.name}
                    </option>
                  ))}
                </Form.Select>
                {!isLoadingChannels && selectedGatewayId && gatewayChannels.length === 0 && (
                  <Form.Text className="text-danger" style={{ fontSize: '10px' }}>
                    No Agent Surfaces published on this gateway
                  </Form.Text>
                )}
                {!isLoadingChannels &&
                  selectedGatewayId &&
                  gatewayChannels.length > 0 &&
                  compatibleChannels.length === 0 && (
                    <Form.Text className="text-warning" style={{ fontSize: '10px' }}>
                      No Agent Surfaces with {tpProtocol?.toUpperCase()} protocol on this gateway (
                      {gatewayChannels.length} hidden)
                    </Form.Text>
                  )}
              </Form.Group>
            )}
          </>
        )}
      </div>

      {supportsAgentCard && (
        <div className="config-section">
          <label>Agent Card</label>{' '}
          <Form.Check
            type="checkbox"
            id="tp-override-agent-card"
            label="Override Agent Card Location"
            checked={overrideAgentCard}
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
          <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
            By default, the gateway fetches the agent card from the configured endpoint plus{' '}
            <code>/.well-known/agent-card.json</code>. Enable this to fetch the card from a custom
            path at that endpoint's origin.
          </Form.Text>
          {overrideAgentCard && (
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
                  endpoint={config.target_endpoint}
                  customPath={config.agent_card_path}
                />
              </Form.Text>
            </Form.Group>
          )}
        </div>
      )}

      <div className="config-section">
        <label>Target Authentication</label>
        <Form.Select
          size="sm"
          value={config.auth_type || 'none'}
          onChange={e => updateField('auth_type', e.target.value)}
        >
          <option value="none">None</option>
          <option value="bearer">Bearer Token</option>
          <option value="api_key">API Key Header</option>
          <option value="custom_header">Custom Header</option>
          <option value="oauth_client_credentials">OAuth Client Credentials</option>
        </Form.Select>
        {config.auth_type && config.auth_type !== 'none' && (
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Secret Reference</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              placeholder="secret-name"
              value={config.auth_secret || ''}
              onChange={e => updateField('auth_secret', e.target.value)}
            />
          </Form.Group>
        )}
        {(config.auth_type === 'api_key' || config.auth_type === 'custom_header') && (
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Header Name</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              placeholder={config.auth_type === 'api_key' ? 'X-API-Key' : 'X-Auth'}
              value={config.auth_header_name || ''}
              onChange={e => updateField('auth_header_name', e.target.value)}
            />
          </Form.Group>
        )}
        {config.auth_type === 'custom_header' && (
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Header Format</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              placeholder="{value}"
              value={config.auth_header_format || ''}
              onChange={e => updateField('auth_header_format', e.target.value)}
            />
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Use <code>{'{value}'}</code> as the placeholder for the secret value.
            </Form.Text>
          </Form.Group>
        )}
        {config.auth_type && config.auth_type !== 'none' && (
          <Form.Group className="mt-2">
            <Form.Label className="small text-muted mb-1">Fallback when secret missing</Form.Label>
            <Form.Select
              size="sm"
              value={config.auth_fallback || 'reject'}
              onChange={e => updateField('auth_fallback', e.target.value)}
            >
              <option value="reject">Reject (502)</option>
              <option value="passthrough">Passthrough (no credential injected)</option>
            </Form.Select>
          </Form.Group>
        )}
        {config.auth_type === 'oauth_client_credentials' && (
          <Form.Text className="text-warning" style={{ fontSize: '10px' }}>
            Not yet wired through the proxy runtime — this selection will not be persisted on save.
          </Form.Text>
        )}
      </div>

      <CredentialBindingMount
        rawValue={config.transit_credentials}
        onChange={next => updateField('transit_credentials', next)}
      />

      {isFabricEndpoint(config.target_endpoint) &&
        (hasOutboundCredentialBindings(allNodes) || !!config.transit_credentials) && (
          <FabricDelegatedCredentialsSection
            testIdPrefix="transit-point"
            instanceKey={config.id}
            checked={config.fabric_delegated_credentials === true}
            peerName={
              gateways.find(
                g => g.id === fabricPeerGatewayId(config.target_endpoint, selectedGatewayId)
              )?.name
            }
            onChange={next => updateField('fabric_delegated_credentials', next)}
          />
        )}

      <div className="config-section">
        <label>Security</label>
        <Form.Group className="mb-2">
          <Form.Check
            type="switch"
            id={`tp-require-transit-token-${config.id || 'new'}`}
            label="Require transit token"
            checked={config.require_transit_token !== false}
            onChange={e => updateField('require_transit_token', e.target.checked)}
          />
          <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
            When enabled, every call to this transit point must carry a valid{' '}
            <code>X-Transit-Token</code> header issued by the surface's Access Point. Disable only
            for development or when the caller cannot carry the token — requests will then be
            forwarded without caller-context enforcement.
          </Form.Text>
        </Form.Group>
      </div>
    </>
  );
};

interface CredentialBindingMountProps {
  rawValue: any;
  onChange: (next: TransitCredentialsForm | null) => void;
}

/**
 * Bridges between the persisted shape on the node and the form shape
 * the section expects. The node may carry either:
 *   • the API shape (after hydration from `transit.points[i].transit_credentials`), or
 *   • the form shape (after the user edited it in this session).
 * On first render we normalize API → form so the section always sees
 * the form representation. The factory converts back to API on save.
 */
const CredentialBindingMount: React.FC<CredentialBindingMountProps> = ({ rawValue, onChange }) => {
  const normalizedRef = React.useRef(false);
  useEffect(() => {
    if (normalizedRef.current) return;
    if (rawValue && typeof rawValue === 'object' && !('inject_as_type' in rawValue)) {
      const form = transitCredentialsApiToForm(rawValue);
      if (form) {
        normalizedRef.current = true;
        onChange(form);
        return;
      }
    }
    normalizedRef.current = true;
  }, [rawValue, onChange]);

  const value: TransitCredentialsForm | null =
    rawValue && typeof rawValue === 'object' && 'inject_as_type' in rawValue
      ? (rawValue as TransitCredentialsForm)
      : null;

  return <TransitCredentialBindingSection value={value} onChange={onChange} />;
};

export default TransitPointPanel;
