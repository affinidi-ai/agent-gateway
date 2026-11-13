import React, { useEffect, useMemo } from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
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
import TargetAuthProviderSelect from '../_shared/TargetAuthProviderSelect';
import {
  PROVIDER_TARGET_AUTH_DEFAULTS,
  providerTargetAuthFromApi,
} from '../_shared/providerTargetAuth';
import TransitCallerSection from './TransitCallerSection';
import TargetAuthSecretField from './TargetAuthSecretField';
import { newTransitPointId, deriveTransitPointAlias } from './factory';
import GatewaySurfacePicker from '../_shared/GatewaySurfacePicker';
import {
  loadFabricGateways,
  parseFabricEndpoint,
  surfaceMatchesProtocol,
  useGatewaySurfaces,
} from '../_shared/useGatewaySurfaces';

type EndpointType = 'url' | 'gateway';

const isFabricEndpoint = (endpoint: unknown): endpoint is string =>
  typeof endpoint === 'string' && endpoint.startsWith('fabric://');

export const inferEndpointType = (config: ConfigPanelProps['config']): EndpointType =>
  config.endpoint_type || (isFabricEndpoint(config.target_endpoint) ? 'gateway' : 'url');

/** The gateway and surface of a gateway route, read from the saved `fabric://` URL when the picker fields are absent. */
export function transitPointGatewayRoute(config: ConfigPanelProps['config']): {
  gatewayId: string;
  surfaceId: string;
} {
  const fromUrl = parseFabricEndpoint(config.target_endpoint);
  return {
    gatewayId: config.gateway_id || fromUrl?.gatewayId || '',
    surfaceId: config.gateway_channel || fromUrl?.surfaceId || '',
  };
}

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
  errorByField,
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
    const provider = providerTargetAuthFromApi(ta);
    if (provider) {
      authHydratedRef.current = true;
      updateFields({
        auth_type: 'credential_provider',
        auth_provider_id: provider.providerId,
        auth_header_name: provider.headerName,
        auth_header_format: provider.headerFormat,
        auth_fallback: provider.fallback,
      });
      return;
    }
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

  const endpointType = inferEndpointType(config);
  const { gatewayId, surfaceId } = transitPointGatewayRoute(config);
  const gatewayState = useGatewaySurfaces({
    enabled: endpointType === 'gateway',
    gatewayId,
    loadGateways: loadFabricGateways,
  });

  // HTTP transit points are protocol-agnostic pass-throughs, so they list every remote surface.
  const filterProtocol = tpProtocol === 'http' ? null : tpProtocol;
  const compatibleSurfaces = useMemo(
    () => gatewayState.surfaces.filter(s => surfaceMatchesProtocol(s, filterProtocol)),
    [gatewayState.surfaces, filterProtocol]
  );

  const selectGateway = (id: string) => {
    if (id === gatewayId) return;
    updateFields({
      gateway_id: id,
      gateway_channel: '',
      target_endpoint: '',
      fabric_remote_gateway_name: undefined,
      fabric_remote_channel_name: undefined,
    });
  };

  const selectSurface = (id: string) => {
    const surface = compatibleSurfaces.find(s => s.config_id === id);
    const gateway = gatewayState.gateways.find(g => g.id === gatewayId);
    updateFields({
      gateway_id: gatewayId,
      gateway_channel: id,
      target_endpoint: id ? `fabric://${gatewayId}/${id}` : '',
      fabric_remote_channel_name: surface?.name,
      fabric_remote_gateway_name: config.fabric_remote_gateway_name || gateway?.name,
    });
  };

  const handleEndpointTypeChange = (newType: EndpointType) => {
    const directEndpoint = isFabricEndpoint(config.target_endpoint)
      ? ''
      : config.target_endpoint || '';

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
        bannerTestId="transit-point-listener-url"
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
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label
              htmlFor="transit-point-endpoint-type-select"
              className="small text-muted mb-0"
            >
              Endpoint Type
            </Form.Label>
            <FieldHelp
              testId="field-help-transit-point-endpoint-type"
              ariaLabel="About Endpoint Type"
            >
              <p>Choose where this route sends the Managed Agent&apos;s outbound calls:</p>
              <p>
                <strong>Direct URL</strong>: type in the destination&apos;s own web address.
              </p>
              <p>
                <strong>via Gateway Connection</strong>: reach an Agent Surface published by another
                Agent Gateway you&apos;re connected to, over the Fabric.
              </p>
            </FieldHelp>
          </div>
          <Form.Select
            id="transit-point-endpoint-type-select"
            size="sm"
            data-testid="transit-point-endpoint-type-select"
            value={endpointType}
            onChange={e => handleEndpointTypeChange(e.target.value as EndpointType)}
          >
            <option value="url">Direct URL</option>
            <option value="gateway">via Gateway Connection</option>
          </Form.Select>
        </Form.Group>

        {endpointType === 'url' && (
          <Form.Group className="mb-2">
            <Form.Label
              htmlFor="transit-point-target-endpoint-input"
              className="small text-muted mb-1"
            >
              Target Endpoint URL <span className="text-danger">*</span>
            </Form.Label>
            <Form.Control
              id="transit-point-target-endpoint-input"
              size="sm"
              type="text"
              data-testid="transit-point-target-endpoint-input"
              value={config.target_endpoint || ''}
              onChange={e => updateField('target_endpoint', e.target.value)}
              isInvalid={!!errorByField?.target_endpoint}
            />
            {errorByField?.target_endpoint ? (
              <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
                {errorByField.target_endpoint}
              </Form.Control.Feedback>
            ) : (
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Full URL including protocol (http:// or https://)
              </Form.Text>
            )}
          </Form.Group>
        )}

        {endpointType === 'gateway' && (
          <GatewaySurfacePicker
            testIdPrefix="transit-point"
            state={gatewayState}
            gatewayId={gatewayId}
            surfaceId={surfaceId}
            surfaces={compatibleSurfaces}
            onGatewayChange={selectGateway}
            onSurfaceChange={selectSurface}
            gatewayLabel="Gateway"
            gatewayPlaceholder="Select a gateway…"
            gatewayHelp={
              <p className="mb-0">
                Pick the connected remote Agent Gateway that publishes the destination. After
                picking one, choose the Agent Surface on it to route to.
              </p>
            }
            noGatewayTitle="No connected gateway"
            noGatewayText="Connect another Agent Gateway first, then select it here."
            savedGatewayName={config.fabric_remote_gateway_name}
            surfaceLabel="Agent Surface on Gateway"
            surfacePlaceholder="Select an Agent Surface…"
            surfaceHelp={
              <p className="mb-0">
                The Agent Surfaces this gateway publishes
                {filterProtocol ? ` for ${filterProtocol.toUpperCase()}` : ''}, loaded live from it.
                Refresh loads the list again.
              </p>
            }
            emptySurfacesText="The remote gateway reported no published Agent Surfaces. Publish one there, then Refresh."
            hiddenSurfacesText={
              filterProtocol
                ? `No ${filterProtocol.toUpperCase()} Agent Surfaces on this gateway (${gatewayState.surfaces.length} of other protocols hidden).`
                : undefined
            }
          />
        )}
      </div>

      {supportsAgentCard && endpointType === 'url' && !isFabricEndpoint(config.target_endpoint) && (
        <div className="config-section">
          <label>Agent Card</label>{' '}
          <div className="d-flex align-items-center gap-1">
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
            <FieldHelp
              testId="field-help-transit-point-agent-card"
              ariaLabel="About Override Agent Card Location"
            >
              <p className="mb-0">
                By default, the gateway fetches the agent card from the configured endpoint plus{' '}
                <code>/.well-known/agent-card.json</code>. Enable this to fetch the card from a
                custom path at that endpoint&apos;s origin.
              </p>
            </FieldHelp>
          </div>
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
          data-testid="transit-point-target-auth-type"
          value={config.auth_type || 'none'}
          onChange={e => updateField('auth_type', e.target.value)}
        >
          <option value="none">None</option>
          <option value="bearer">Bearer Token</option>
          <option value="api_key">API Key Header</option>
          <option value="custom_header">Custom Header</option>
          <option value="credential_provider">Credential Provider</option>
        </Form.Select>
        {config.auth_type === 'credential_provider' && (
          <>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1" htmlFor="transit-point-auth-provider">
                Credential Provider
              </Form.Label>
              <TargetAuthProviderSelect
                id="transit-point-auth-provider"
                testId="transit-point-target-auth-provider"
                value={config.auth_provider_id || ''}
                onChange={providerId => updateField('auth_provider_id', providerId)}
                small
              />
            </Form.Group>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Header Name</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                data-testid="transit-point-target-auth-provider-header-name"
                placeholder={PROVIDER_TARGET_AUTH_DEFAULTS.headerName}
                value={config.auth_header_name || ''}
                onChange={e => updateField('auth_header_name', e.target.value)}
              />
            </Form.Group>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Header Format</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                data-testid="transit-point-target-auth-provider-header-format"
                placeholder={PROVIDER_TARGET_AUTH_DEFAULTS.headerFormat}
                value={config.auth_header_format || ''}
                onChange={e => updateField('auth_header_format', e.target.value)}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Use <code>{'{value}'}</code> as the placeholder for the provider's token.
              </Form.Text>
            </Form.Group>
          </>
        )}
        {config.auth_type &&
          config.auth_type !== 'none' &&
          config.auth_type !== 'credential_provider' && (
            <TargetAuthSecretField
              value={config.auth_secret || ''}
              onChange={secretId => updateField('auth_secret', secretId)}
              error={errorByField?.auth_secret}
            />
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
            <Form.Label className="small text-muted mb-1">
              Fallback when the credential is missing
            </Form.Label>
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
      </div>

      <CredentialBindingMount
        rawValue={config.transit_credentials}
        onChange={next => updateField('transit_credentials', next)}
      />

      {isFabricEndpoint(config.target_endpoint) &&
        (hasOutboundCredentialBindings(allNodes) ||
          !!config.transit_credentials?.credential_provider_id) && (
          <FabricDelegatedCredentialsSection
            testIdPrefix="transit-point"
            instanceKey={config.id}
            checked={config.fabric_delegated_credentials === true}
            peerName={
              gatewayState.gateways.find(
                g => g.id === fabricPeerGatewayId(config.target_endpoint, gatewayId)
              )?.name
            }
            onChange={next => updateField('fabric_delegated_credentials', next)}
          />
        )}

      <TransitCallerSection
        config={config}
        alias={alias}
        updateField={updateField}
        updateFields={updateFields}
      />
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
