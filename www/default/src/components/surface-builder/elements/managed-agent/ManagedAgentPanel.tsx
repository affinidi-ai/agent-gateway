import React, { useState, useEffect, useMemo } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import { ENABLE_MPP_PAYWALL } from '../../../../utils/featureFlags';
import { filterSelectableGateways } from '../../../../utils/gateways';
import type { ConfigPanelProps } from '../types';
import { RouteListenerBanner } from '../_shared/RouteListenerSection';
import FieldHelp from '../../../shared/FieldHelp';
import A2aProxyEndpointFields, { type A2aProxyOption } from './A2aProxyEndpointFields';

interface Gateway {
  id: string;
  name: string;
  gateway_type: string;
  creation_type: string;
}

interface GatewayChannel {
  config_id: string;
  name: string;
  protocol?: string;
}

interface McpProxy {
  id: string;
  name: string;
  /** Absent on a gateway that predates it, which serves every proxy directly. */
  direct_access?: boolean;
}

const ManagedAgentPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  errorByField,
  openFullscreenEditor,
  allNodes,
}) => {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [gatewayChannels, setGatewayChannels] = useState<GatewayChannel[]>([]);
  const [isLoadingChannels, setIsLoadingChannels] = useState(false);
  const [channelsError, setChannelsError] = useState<string | null>(null);
  const [channelsRefreshTick, setChannelsRefreshTick] = useState(0);
  const [mcpProxies, setMcpProxies] = useState<McpProxy[]>([]);
  const [a2aProxies, setA2aProxies] = useState<A2aProxyOption[]>([]);

  // Fully controlled — every "form field" is read from `config` so undo/redo
  // and reload-from-server both reflect immediately. Local useState mirrors
  // would silently drift from the saved wire shape (e.g. a saved
  // `fabric://...` endpoint would render as Direct URL on reload).
  const endpointType: 'url' | 'gateway' | 'mcp-proxy' | 'a2a-proxy' = config.endpoint_type || 'url';
  const selectedGatewayId: string = config.gateway_id || '';
  const selectedGatewayChannel: string = config.gateway_channel || '';

  useEffect(() => {
    apiClient
      .get('/gateways')
      .then(res => {
        setGateways(filterSelectableGateways(res.data));
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (endpointType !== 'mcp-proxy') return;
    apiClient
      .get('/mcp-proxies')
      .then(res => {
        const list = Array.isArray(res.data) ? res.data : res.data?.proxies || [];
        setMcpProxies(list);
      })
      .catch(() => setMcpProxies([]));
  }, [endpointType]);

  useEffect(() => {
    if (endpointType !== 'a2a-proxy') return;
    apiClient
      .get('/a2a-proxies')
      .then(res => {
        const list = Array.isArray(res.data) ? res.data : res.data?.proxies || [];
        setA2aProxies(list);
      })
      .catch(() => setA2aProxies([]));
  }, [endpointType]);

  useEffect(() => {
    if (!selectedGatewayId || endpointType !== 'gateway') return;
    setIsLoadingChannels(true);
    setChannelsError(null);
    const force = channelsRefreshTick > 0 ? '?force_refresh=true' : '';
    apiClient
      .get(`/gateways/${selectedGatewayId}/surfaces${force}`)
      .then(res => {
        const data = res.data;
        const channels = Array.isArray(data) ? data : data?.channels || [];
        setGatewayChannels(channels);
      })
      .catch(err => {
        setGatewayChannels([]);
        const msg = err?.message || String(err);
        if (msg.toLowerCase().includes('not connected') || msg.includes('503')) {
          setChannelsError(
            'Gateway is not currently connected. Channel list cannot be fetched until the remote gateway re-establishes its WebSocket session.'
          );
        } else if (msg.includes('404')) {
          setChannelsError('Gateway not found.');
        } else {
          setChannelsError(`Failed to load channels: ${msg}`);
        }
      })
      .finally(() => setIsLoadingChannels(false));
  }, [selectedGatewayId, endpointType, channelsRefreshTick]);

  // Convenience banner: show the Access Point's listener URL so the
  // user can see at a glance where this Managed Agent will be reached
  // from. Read-only — the AP panel owns the actual listener config.
  const accessPointUrl: string = useMemo(() => {
    const ap = allNodes?.find(n => n.type === 'access-point');
    const apc: any = ap?.config ?? {};
    const listen: string = (apc.listen_address || '').trim();
    const route: string = (apc.route || '').trim();
    if (!listen || !route) return '';
    const base = listen.replace(/\/$/, '');
    const path = route.startsWith('/') ? route : `/${route}`;
    return `${base}${path}`;
  }, [allNodes]);

  return (
    <>
      <RouteListenerBanner
        label="Reached at"
        url={accessPointUrl}
        placeholder="(configure the Access Point to derive a URL)"
      />

      <div className="config-section">
        <label>Endpoint</label>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">Endpoint Type</Form.Label>
            <FieldHelp
              testId="field-help-managed-agent-endpoint-type"
              ariaLabel="About Endpoint Type"
            >
              <p>Choose how the gateway reaches the real agent behind this node:</p>
              <p>
                <strong>Direct URL</strong>: type in the agent's own web address; simplest for a
                standalone external agent.
              </p>
              <p>
                <strong>via Gateway Connection</strong>: reach an agent published by another Agent
                Gateway you're connected to.
              </p>
              <p>
                <strong>via MCP Proxy</strong> (MCP surfaces only): route through a managed proxy
                that fronts a set of tools.
              </p>
              <p>
                <strong>via A2A Proxy</strong> (A2A or AP2 surfaces only): route through a proxy
                that adapts a non-A2A backend, like Microsoft Copilot Studio, to speak A2A.
              </p>
              <p>If unsure, start with Direct URL.</p>
            </FieldHelp>
          </div>
          <Form.Select
            size="sm"
            value={endpointType}
            onChange={e => {
              const newType = e.target.value as 'url' | 'gateway' | 'mcp-proxy' | 'a2a-proxy';
              const patch: Record<string, any> = { endpoint_type: newType };
              if (newType !== 'gateway') {
                patch.gateway_id = '';
                patch.gateway_channel = '';
              }
              if (newType !== 'mcp-proxy') {
                patch.mcp_proxy_id = '';
              }
              if (newType !== 'a2a-proxy') {
                patch.a2a_proxy_id = '';
              }
              // Always reset endpoint when type changes — the previous
              // value (url / fabric:// / proxy://) is meaningless under the
              // new type and the per-type branches below repopulate it.
              patch.endpoint = '';
              // The synth chain (hop / remote / remote-channel) reuses the
              // same name fields for both fabric:// and proxy:// flavours.
              // Clear them so a label the user set for a gateway hop
              // doesn't bleed into the MCP proxy chain (and vice-versa).
              patch.fabric_hop_name = '';
              patch.fabric_remote_gateway_name = '';
              patch.fabric_remote_channel_name = '';
              updateFields(patch);
            }}
          >
            <option value="url">Direct URL</option>
            <option value="gateway">via Gateway Connection</option>
            {protocol === 'mcp' && <option value="mcp-proxy">via MCP Proxy</option>}
            {(protocol === 'a2a' || protocol === 'ap2') && (
              <option value="a2a-proxy">via A2A Proxy</option>
            )}
          </Form.Select>
        </Form.Group>

        {endpointType === 'url' && (
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">
              Target Endpoint URL <span className="text-danger">*</span>
            </Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={config.endpoint || ''}
              onChange={e => updateField('endpoint', e.target.value)}
              isInvalid={!!errorByField?.endpoint}
            />
            {errorByField?.endpoint ? (
              <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
                {errorByField.endpoint}
              </Form.Control.Feedback>
            ) : (
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Full URL including protocol (http:// or https://)
              </Form.Text>
            )}
          </Form.Group>
        )}

        {endpointType === 'gateway' && (
          <>
            <Form.Group className="mb-2">
              <div className="d-flex align-items-center gap-1 mb-1">
                <Form.Label className="small text-muted mb-0">Gateway</Form.Label>
                <FieldHelp testId="field-help-managed-agent-gateway" ariaLabel="About Gateway">
                  <p>
                    Pick which connected remote Agent Gateway hosts the actual agent you want to
                    reach (a gateway your team has already connected to, not a general internet
                    address).
                  </p>
                  <p>
                    After picking one, you'll choose the specific agent surface on it to target.
                  </p>
                </FieldHelp>
              </div>
              <Form.Select
                size="sm"
                value={selectedGatewayId}
                onChange={e => {
                  const gwId = e.target.value;
                  setGatewayChannels([]);
                  updateFields({ gateway_id: gwId, gateway_channel: '', endpoint: '' });
                }}
              >
                <option value="">-- Select a Gateway --</option>
                {gateways.map(gw => (
                  <option key={gw.id} value={gw.id}>
                    {gw.name}
                  </option>
                ))}
              </Form.Select>
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                {gateways.length === 0
                  ? 'No remote gateways connected yet. '
                  : "Don't see the one you need? "}
                <AddResourceLink
                  to={deepLinks.remoteGateway}
                  testid="managed-agent-add-gateway-link"
                >
                  Add Gateway
                </AddResourceLink>
              </Form.Text>
            </Form.Group>
            {selectedGatewayId &&
              (() => {
                const filteredChannels = protocol
                  ? gatewayChannels.filter(
                      ch => !ch.protocol || ch.protocol.toLowerCase() === protocol.toLowerCase()
                    )
                  : gatewayChannels;
                return (
                  <Form.Group className="mb-2">
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <div className="d-flex align-items-center gap-1">
                        <Form.Label className="small text-muted mb-0">
                          Agent Surface on Gateway
                        </Form.Label>
                        <FieldHelp
                          testId="field-help-managed-agent-agent-surface-on-gateway"
                          ariaLabel="About Agent Surface on Gateway"
                        >
                          <p>
                            Choose which agent (an "Agent Surface") on the selected remote gateway
                            this node should call.
                          </p>
                          <p>
                            The list loads live from that gateway; if it's empty, either nothing
                            matching this protocol has been published there yet, or the gateway is
                            temporarily offline. Use refresh to try again.
                          </p>
                        </FieldHelp>
                      </div>
                      <button
                        type="button"
                        className="btn btn-link btn-sm p-0"
                        style={{ fontSize: '10px' }}
                        title="Refresh channel list from gateway"
                        onClick={() => setChannelsRefreshTick(t => t + 1)}
                        disabled={isLoadingChannels}
                      >
                        <i className={`fas fa-sync-alt ${isLoadingChannels ? 'fa-spin' : ''}`} />
                      </button>
                    </div>
                    <Form.Select
                      size="sm"
                      value={selectedGatewayChannel}
                      onChange={e => {
                        const chId = e.target.value;
                        const ch = filteredChannels.find(c => c.config_id === chId);
                        const gw = gateways.find(g => g.id === selectedGatewayId);
                        // Auto-populate the synth chain display
                        // names from the real gateway/channel names
                        // so the canvas reads sensibly straight
                        // away. Existing user overrides are kept.
                        const patch: Record<string, any> = {
                          gateway_channel: chId,
                          endpoint: `fabric://${selectedGatewayId}/${chId}`,
                        };
                        if (!config.fabric_remote_channel_name && ch?.name) {
                          patch.fabric_remote_channel_name = ch.name;
                        }
                        if (!config.fabric_remote_gateway_name && gw?.name) {
                          patch.fabric_remote_gateway_name = gw.name;
                        }
                        updateFields(patch);
                      }}
                      disabled={isLoadingChannels || filteredChannels.length === 0}
                    >
                      <option value="">
                        {isLoadingChannels
                          ? '-- Loading Agent Surfaces... --'
                          : '-- Select an Agent Surface --'}
                      </option>
                      {filteredChannels.map(ch => (
                        <option key={ch.config_id} value={ch.config_id}>
                          {ch.name}
                        </option>
                      ))}
                    </Form.Select>
                    {!isLoadingChannels && channelsError && (
                      <Form.Text className="text-danger" style={{ fontSize: '10px' }}>
                        {channelsError}
                      </Form.Text>
                    )}
                    {!isLoadingChannels &&
                      !channelsError &&
                      filteredChannels.length === 0 &&
                      selectedGatewayId && (
                        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                          {gatewayChannels.length === 0
                            ? 'The remote gateway reported no published Agent Surfaces.'
                            : `No ${protocol?.toUpperCase() || ''} Agent Surfaces on this gateway (${gatewayChannels.length} of other protocols hidden).`}
                        </Form.Text>
                      )}
                  </Form.Group>
                );
              })()}
            <Form.Group className="mb-2">
              <Form.Label className="small text-muted mb-1">Display name (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="Cached Agent Surface name"
                value={config.fabric_target_name || ''}
                onChange={e => updateField('fabric_target_name', e.target.value)}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Cached name is used when the remote Gateway is offline.
              </Form.Text>
            </Form.Group>
          </>
        )}

        {endpointType === 'mcp-proxy' && (
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">MCP Proxy</Form.Label>
            <Form.Select
              size="sm"
              value={config.mcp_proxy_id || ''}
              onChange={e => {
                const id = e.target.value;
                updateFields({
                  mcp_proxy_id: id,
                  endpoint: id ? `proxy://${id}` : '',
                });
              }}
            >
              <option value="">Select an MCP proxy…</option>
              {mcpProxies.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id}
                </option>
              ))}
              {/* Keep the saved value selectable even if the proxy list
                  hasn't loaded or the proxy was removed, so the user
                  doesn't accidentally clear the binding on reopen. */}
              {config.mcp_proxy_id && !mcpProxies.some(p => p.id === config.mcp_proxy_id) && (
                <option value={config.mcp_proxy_id}>{config.mcp_proxy_id} (not found)</option>
              )}
            </Form.Select>
            <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
              Managed MCP proxy that fronts this agent's tools.
            </Form.Text>
            {(() => {
              const selected = mcpProxies.find(p => p.id === config.mcp_proxy_id);
              if (!selected) return null;
              return selected.direct_access === false ? (
                <Form.Text
                  className="d-block text-info"
                  style={{ fontSize: '10px' }}
                  data-testid="managed-agent-proxy-surface-only"
                >
                  <i className="fas fa-shield-alt me-1" aria-hidden="true" />
                  This proxy is served only through surfaces, so this surface&apos;s authentication
                  and policies are what protect it.
                </Form.Text>
              ) : (
                <Form.Text
                  className="d-block text-warning"
                  style={{ fontSize: '10px' }}
                  data-testid="managed-agent-proxy-direct"
                >
                  <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
                  This proxy is also served on its own route, where no sign-in or policy applies, so
                  callers can reach it around this surface. Turn that off on the proxy&apos;s
                  Routing tab.
                </Form.Text>
              );
            })()}
          </Form.Group>
        )}

        {endpointType === 'a2a-proxy' && (
          <A2aProxyEndpointFields
            selectedProxyId={config.a2a_proxy_id || ''}
            a2aProxies={a2aProxies}
            updateFields={updateFields}
          />
        )}
      </div>

      {(endpointType === 'url' || endpointType === 'gateway') && (
        <div className="config-section">
          <label>Target Authentication</label>
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">Authentication Type</Form.Label>
              <FieldHelp
                testId="field-help-managed-agent-authentication-type"
                ariaLabel="About Authentication Type"
              >
                <p>
                  Choose how the gateway should prove its identity to the target when calling it.
                </p>
                <p>
                  <strong>None</strong>: no credentials sent, for targets with no auth. This is the
                  default until you have a reason to add credentials.
                </p>
                <p>
                  Otherwise, pick the format the target expects. You'll fill in the exact secret and
                  header on the next screen.
                </p>
              </FieldHelp>
            </div>
            <Form.Select
              size="sm"
              value={config.target_auth_enabled ? config.target_auth_type || 'bearer' : 'none'}
              onChange={e => {
                const v = e.target.value;
                if (v === 'none') {
                  updateField('target_auth_enabled', false);
                } else {
                  const defaults: Record<string, { headerName: string; headerFormat: string }> = {
                    bearer: { headerName: 'Authorization', headerFormat: 'Bearer {value}' },
                    basic: { headerName: 'Authorization', headerFormat: 'Basic {value}' },
                    api_key: { headerName: 'X-API-Key', headerFormat: '{value}' },
                    custom: { headerName: 'Authorization', headerFormat: '{value}' },
                  };
                  const d = defaults[v] || defaults.bearer;
                  updateFields({
                    target_auth_enabled: true,
                    target_auth_type: v,
                    target_auth_header_name: config.target_auth_header_name || d.headerName,
                    target_auth_header_format: config.target_auth_header_format || d.headerFormat,
                    target_auth_fallback: config.target_auth_fallback || 'reject',
                  });
                }
              }}
            >
              <option value="none">None</option>
              <option value="bearer">Bearer Token</option>
              <option value="basic">Basic Auth</option>
              <option value="api_key">API Key</option>
              <option value="custom">Custom</option>
            </Form.Select>
          </Form.Group>
          {config.target_auth_enabled && (
            <button
              className="btn btn-outline-primary btn-sm w-100"
              onClick={() => openFullscreenEditor?.()}
              disabled={!openFullscreenEditor}
            >
              <i className="fas fa-pen-to-square me-1" /> Configure…
            </button>
          )}
        </div>
      )}

      <div className="config-section">
        <label>Identity Binding VP</label>
        <Form.Check
          type="switch"
          id="inject-identity-vp"
          label={
            <span className="d-flex align-items-center gap-1">
              Send signed identity VP to target
              <FieldHelp
                testId="field-help-managed-agent-send-signed-identity-vp-to-target"
                ariaLabel="About Send signed identity VP to target"
              >
                <p>
                  When this is on, the gateway attaches a small, tamper-proof digital ID badge,
                  formally called a Verifiable Presentation (VP), to every outbound request.
                </p>
                <p>
                  That badge can carry the agent's own identity, and/or information about the human
                  or system that originally called in (captured upstream by a Caller Context
                  element), whichever this surface actually has set up.
                </p>
                <p>
                  If neither is set up, no badge is sent. Check the gateway logs for a "skipped"
                  entry if you expect one but don't see it.
                </p>
              </FieldHelp>
            </span>
          }
          checked={config.inject_vp !== false}
          onChange={e => updateField('inject_vp', e.target.checked)}
        />
      </div>

      {ENABLE_MPP_PAYWALL && config.endpoint?.startsWith('fabric://') && (
        <div className="config-section">
          <label>MPP Auto-Pay</label>
          <Form.Check
            type="switch"
            id="mpp-autopay"
            label="Automatically pay MPP challenges"
            checked={config.mpp_auto_pay || false}
            onChange={e => updateField('mpp_auto_pay', e.target.checked)}
          />
          {config.mpp_auto_pay && (
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Max amount per request</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="1.00"
                value={config.mpp_auto_pay_max_amount || ''}
                onChange={e => updateField('mpp_auto_pay_max_amount', e.target.value)}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                A safety cap on the amount per request. This isn&apos;t tied to a specific currency:
                set it assuming the same denomination the target&apos;s payment challenges will use
                (for example, USD for a card-based target, or the token&apos;s base unit for a
                crypto-based one). The gateway compares the numbers only, it doesn&apos;t convert or
                verify units.
              </Form.Text>
            </Form.Group>
          )}
        </div>
      )}
    </>
  );
};

export default ManagedAgentPanel;
