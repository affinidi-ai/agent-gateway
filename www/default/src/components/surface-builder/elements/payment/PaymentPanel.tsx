import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import InfoBanner from '../../../shared/InfoBanner';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../../../api';
import { useApp } from '../../../../context/AppContext';
import type { ConfigPanelProps } from '../types';
import MppSecretField from './MppSecretField';

/**
 * Compact sidebar panel for the Payment element. Supports two kinds:
 *  - **x402**: HTTP 402 paywall (heavy config in the per-element fullscreen).
 *  - **mpp**: Machine Payments Protocol (inline minimal config — realm,
 *    secret key, payment methods, optional protocol triggers).
 *
 * Both kinds project to `target.payment_policy` with the appropriate
 * discriminant. Only one kind can be active per Surface; switching kinds
 * preserves the other kind's config under a namespaced field so the user
 * doesn't lose their work.
 */
const PaymentPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  updateFields,
  protocol,
  openFullscreenEditor,
  hasAttemptedSave = false,
}) => {
  const enabled = !!config.enabled;
  const kind: 'x402' | 'mpp' = config.payment_kind === 'mpp' ? 'mpp' : 'x402';
  const isPaymentSupported = protocol === 'mcp' || protocol === 'a2a';

  // Model B: delegate the whole paywall to a connected Agent-Pay gateway.
  const provider: 'local' | 'agent_pay' = config.provider === 'agent_pay' ? 'agent_pay' : 'local';
  // Gate the Agent-Pay delegation option behind a server-driven feature flag;
  // a surface already set to delegate stays editable regardless of the flag.
  const { state } = useApp();
  const showAgentPay =
    state.settings?.feature_flags?.agent_pay_delegation === true || provider === 'agent_pay';
  const navigate = useNavigate();
  const [peerGateways, setPeerGateways] = useState<Array<{ id: string; name?: string }>>([]);
  const [gatewaysLoaded, setGatewaysLoaded] = useState(false);
  const [channels, setChannels] = useState<
    Array<{
      config_id: string;
      name: string;
      tags: string[];
      is_payment_surface: boolean | null;
    }>
  >([]);
  const [channelsLoading, setChannelsLoading] = useState(false);
  const [channelsError, setChannelsError] = useState<string | null>(null);
  const [channelsRefreshTick, setChannelsRefreshTick] = useState(0);
  const [manualEntry, setManualEntry] = useState(false);
  const [paymentOnly, setPaymentOnly] = useState(true);
  const [paymentGatewayIds, setPaymentGatewayIds] = useState<Set<string> | null>(null);
  const selectedGatewayId: string = config.payment_gateway_id || '';

  useEffect(() => {
    if (provider !== 'agent_pay') return;
    let cancelled = false;
    apiClient
      .get<any[]>('/gateways')
      .then(({ data }) => {
        if (cancelled) return;
        const remotes = (data || []).filter(
          (gw: any) => gw.gateway_type === 'remote' && gw.creation_type === 'user'
        );
        setPeerGateways(remotes.map((gw: any) => ({ id: gw.id, name: gw.name })));
        setGatewaysLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setPeerGateways([]);
        setGatewaysLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [provider]);

  // Discover the selected gateway's exposed surfaces over the fabric so the
  // payment channel can be picked instead of typed. Reuses the same endpoint
  // as the managed-agent fabric-target channel picker.
  useEffect(() => {
    if (provider !== 'agent_pay' || !selectedGatewayId) {
      setChannels([]);
      setChannelsError(null);
      return;
    }
    let cancelled = false;
    setChannelsLoading(true);
    setChannelsError(null);
    const force = channelsRefreshTick > 0 ? '?force_refresh=true' : '';
    apiClient
      .get<any>(`/gateways/${selectedGatewayId}/surfaces${force}`)
      .then(({ data }) => {
        if (cancelled) return;
        const list = Array.isArray(data) ? data : data?.channels || [];
        setChannels(
          list.map((c: any) => ({
            config_id: c.config_id,
            name: c.name || c.config_id,
            tags: Array.isArray(c.tags) ? c.tags : [],
            is_payment_surface:
              typeof c.is_payment_surface === 'boolean' ? c.is_payment_surface : null,
          }))
        );
      })
      .catch((err: any) => {
        if (cancelled) return;
        setChannels([]);
        const msg = err?.message || String(err);
        setChannelsError(
          msg.toLowerCase().includes('not connected') || msg.includes('503')
            ? 'Gateway not connected, cannot list its payment surfaces. Enter the channel id manually, or retry once it reconnects.'
            : `Could not load channels: ${msg}`
        );
      })
      .finally(() => {
        if (!cancelled) setChannelsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [provider, selectedGatewayId, channelsRefreshTick]);

  // Payment is implicitly enabled whenever the protocol supports it.
  // Seed x402 defaults on first render so the rest of the panel has
  // sensible values to bind to (mirrors the old enable-switch handler).
  useEffect(() => {
    if (!isPaymentSupported) return;
    if (enabled) return;
    if (kind === 'x402' && config.verification_mode === undefined) {
      updateFields({
        enabled: true,
        payment_kind: 'x402',
        verification_mode: 'mock',
        settlement_mode: 'none',
        supported_schemes: ['exact'],
        supported_networks: ['base'],
        payment_requirements: [],
        rpc_endpoints: {},
        min_confirmations: 0,
        accept_mempool_tx: true,
      });
    } else {
      updateField('enabled', true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPaymentSupported]);

  const x402ReqCount = Array.isArray(config.payment_requirements)
    ? config.payment_requirements.length
    : 0;
  const x402NetworkCount = Object.keys(config.rpc_endpoints || {}).length;

  const mppMethods: any[] = useMemo(() => {
    const m = config.mpp_payment_methods;
    if (Array.isArray(m)) return m;
    if (typeof m === 'string' && m.trim()) {
      try {
        const parsed = JSON.parse(m);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  }, [config.mpp_payment_methods]);

  // A discovered surface is a payment delegation target when the remote marks
  // it as an actual payment surface (`is_payment_surface`, an x402/MPP policy)
  // OR when it is exposed through a connection point the operator tagged
  // `payment`. Either signal admits it. A peer that predates both markers sends
  // `is_payment_surface: null` and no tags on every surface — for such legacy
  // peers the filter is a no-op so the existing discovery workflow keeps working.
  const peerSupportsPaymentFilter = useMemo(
    () =>
      channels.some(
        c =>
          (c.is_payment_surface !== null && c.is_payment_surface !== undefined) || c.tags.length > 0
      ),
    [channels]
  );
  const visiblePaymentChannels = useMemo(
    () =>
      paymentOnly && peerSupportsPaymentFilter
        ? channels.filter(c => c.is_payment_surface === true || c.tags.includes('payment'))
        : channels,
    [paymentOnly, peerSupportsPaymentFilter, channels]
  );

  // If the discovered surfaces carry no payment marker at all — e.g. a stale
  // 5-minute discovery cache captured before the Agent-Pay peer was upgraded —
  // force one refresh so the picker can pick up `is_payment_surface`. Guarded
  // to fire at most once per gateway so a genuinely old peer can't loop.
  const autoRefreshedGatewayRef = useRef<string | null>(null);
  useEffect(() => {
    if (provider !== 'agent_pay' || !selectedGatewayId) return;
    if (channelsLoading || channels.length === 0) return;
    if (!paymentOnly || peerSupportsPaymentFilter) return;
    if (autoRefreshedGatewayRef.current === selectedGatewayId) return;
    autoRefreshedGatewayRef.current = selectedGatewayId;
    setChannelsRefreshTick(t => t + 1);
  }, [
    provider,
    selectedGatewayId,
    channelsLoading,
    channels,
    paymentOnly,
    peerSupportsPaymentFilter,
  ]);

  // Ask the gateway which connected peers actually expose a payment surface,
  // so the Payment Gateway picker can hide non-payment peers. The gateway does
  // the (cached, concurrent) discovery + filtering server-side and returns just
  // the payment-capable gateways in a single request — no client-side fan-out.
  // Falls back to showing all peers on error, and when the filter is off.
  useEffect(() => {
    if (provider !== 'agent_pay' || !paymentOnly) {
      setPaymentGatewayIds(null);
      return;
    }
    let cancelled = false;
    apiClient
      .get<Array<{ id: string }>>('/gateways/payment-providers')
      .then(({ data }) => {
        if (cancelled) return;
        setPaymentGatewayIds(new Set((data || []).map(g => g.id)));
      })
      .catch(() => {
        // On error, don't hide anything — fall back to showing all gateways.
        if (!cancelled) setPaymentGatewayIds(null);
      });
    return () => {
      cancelled = true;
    };
  }, [provider, paymentOnly]);

  const visiblePaymentGateways = useMemo(() => {
    // Fall back to all peers until discovery finishes, or when none qualify, so
    // the picker never ends up empty. Always keep the current selection visible.
    if (!paymentOnly || !paymentGatewayIds || paymentGatewayIds.size === 0) {
      return peerGateways;
    }
    return peerGateways.filter(gw => paymentGatewayIds.has(gw.id) || gw.id === selectedGatewayId);
  }, [peerGateways, paymentGatewayIds, paymentOnly, selectedGatewayId]);

  return (
    <>
      {!isPaymentSupported && (
        <div className="config-section">
          <div className="alert alert-info py-2 mb-0" style={{ fontSize: '11px' }}>
            <i className="fas fa-info-circle me-1" /> Payment requires MCP or A2A protocol.
          </div>
        </div>
      )}

      {isPaymentSupported && (
        <>
          {showAgentPay && (
            <div className="config-section">
              <label>Payment Provider</label>
              <Form.Select
                size="sm"
                value={provider}
                onChange={e => {
                  if (e.target.value === 'agent_pay') {
                    updateFields({ enabled: true, provider: 'agent_pay' });
                  } else {
                    updateField('provider', 'local');
                  }
                }}
              >
                <option value="local">This gateway (inline x402 / MPP)</option>
                <option value="agent_pay">Agent Pay (delegate payment)</option>
              </Form.Select>
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Delegate the entire paywall (challenge, verification and settlement) to a connected
                Agent Pay over the fabric.
              </Form.Text>
            </div>
          )}

          {provider === 'agent_pay' && (
            <>
              <div className="config-section">
                <label>Delegated Payment Protocol</label>
                <Form.Select
                  size="sm"
                  value={kind}
                  onChange={e => updateField('payment_kind', e.target.value)}
                >
                  <option value="x402">x402 (the delegate surface enforces x402)</option>
                  <option value="mpp">MPP (the delegate surface enforces MPP)</option>
                </Form.Select>
                <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                  Informational only — the fabric relay forwards either protocol transparently. Set
                  this to match what the selected payment surface actually enforces, for clarity in
                  config and the delegation audit log.
                </Form.Text>
              </div>

              {gatewaysLoaded && peerGateways.length === 0 && (
                <div className="config-section surface-info-panel surface-info-panel--warning">
                  <div className="surface-info-panel-title">
                    <i className="fas fa-plug me-1" />
                    No connected gateway
                  </div>
                  <div className="surface-info-panel-summary">
                    There is no connected gateway to delegate payments to. Connect an Agent-Pay
                    gateway first, then select it here.
                  </div>
                  <button
                    className="btn btn-outline-primary btn-sm w-100 mt-2"
                    onClick={() => navigate('/gateways/connect')}
                  >
                    <i className="fas fa-link me-1" /> Connect a gateway…
                  </button>
                </div>
              )}

              {peerGateways.length > 0 && (
                <>
                  <div className="config-section">
                    <label>Payment Gateway</label>
                    <Form.Check
                      type="switch"
                      id="payment-only-cp-filter"
                      className="mt-1 mb-1"
                      style={{ fontSize: '11px' }}
                      checked={paymentOnly}
                      onChange={e => setPaymentOnly(e.target.checked)}
                      label="Only payment connection points"
                    />
                    <Form.Select
                      size="sm"
                      value={config.payment_gateway_id || ''}
                      onChange={e => updateField('payment_gateway_id', e.target.value)}
                    >
                      <option value="">Select a connected gateway…</option>
                      {visiblePaymentGateways.map(gw => (
                        <option key={gw.id} value={gw.id}>
                          {gw.name || gw.id}
                        </option>
                      ))}
                    </Form.Select>
                    {paymentOnly &&
                      !!paymentGatewayIds &&
                      paymentGatewayIds.size > 0 &&
                      visiblePaymentGateways.length < peerGateways.length && (
                        <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                          Showing only gateways that expose a payment surface. Turn off the filter
                          to see all {peerGateways.length}.
                        </Form.Text>
                      )}
                  </div>

                  {config.payment_gateway_id && (
                    <div className="config-section">
                      <div className="d-flex justify-content-between align-items-center">
                        <label className="mb-0">Payment Surface</label>
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0"
                          style={{ fontSize: '10px' }}
                          onClick={() => setChannelsRefreshTick(t => t + 1)}
                          disabled={channelsLoading}
                        >
                          <i className="fas fa-rotate me-1" />
                          {channelsLoading ? 'Loading…' : 'Refresh'}
                        </button>
                      </div>

                      <Form.Select
                        size="sm"
                        value={config.payment_surface_id || ''}
                        onChange={e => updateField('payment_surface_id', e.target.value)}
                        disabled={channelsLoading}
                      >
                        <option value="">
                          {channelsLoading ? 'Loading…' : 'Select an exposed payment surface…'}
                        </option>
                        {config.payment_surface_id &&
                          !visiblePaymentChannels.some(
                            c => c.config_id === config.payment_surface_id
                          ) && (
                            <option value={config.payment_surface_id}>
                              {config.payment_surface_id} (not currently exposed)
                            </option>
                          )}
                        {visiblePaymentChannels.map(c => (
                          <option key={c.config_id} value={c.config_id}>
                            {c.name && c.name !== c.config_id
                              ? `${c.name} (${c.config_id.slice(0, 8)}…)`
                              : c.config_id}
                          </option>
                        ))}
                      </Form.Select>

                      {channelsError ? (
                        <Form.Text className="text-warning d-block" style={{ fontSize: '10px' }}>
                          <i className="fas fa-triangle-exclamation me-1" />
                          {channelsError}
                        </Form.Text>
                      ) : visiblePaymentChannels.length === 0 && !channelsLoading ? (
                        <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                          {channels.length > 0 && paymentOnly && peerSupportsPaymentFilter
                            ? 'No payment surfaces found on this gateway. Expose a payment surface (or a surface on a connection point tagged “payment”) in Agent-Pay and press Refresh, or turn off the filter above to see all surfaces.'
                            : 'No exposed surfaces discovered. Expose the payment surface on the Agent-Pay gateway, then Refresh.'}
                        </Form.Text>
                      ) : (
                        <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                          Exposed payment surface on the selected gateway.
                        </Form.Text>
                      )}

                      {!channelsLoading && (
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0"
                          style={{ fontSize: '10px' }}
                          onClick={() => setManualEntry(m => !m)}
                        >
                          {manualEntry ? 'Hide manual entry' : 'Enter channel id manually'}
                        </button>
                      )}

                      {manualEntry && (
                        <Form.Control
                          className="mt-1"
                          size="sm"
                          type="text"
                          placeholder="agent-pay payment surface channel id"
                          value={config.payment_surface_id || ''}
                          onChange={e => updateField('payment_surface_id', e.target.value)}
                        />
                      )}
                    </div>
                  )}
                </>
              )}
            </>
          )}

          {provider !== 'agent_pay' && (
            <div className="config-section">
              <label>Payment Protocol</label>
              <Form.Select
                size="sm"
                value={kind}
                onChange={e => updateField('payment_kind', e.target.value)}
              >
                <option value="x402">x402 (HTTP 402 paywall)</option>
                <option value="mpp">MPP (Machine Payments Protocol)</option>
              </Form.Select>
            </div>
          )}

          {provider !== 'agent_pay' && kind === 'x402' && (
            <>
              {hasAttemptedSave && config.settlement_mode === 'none' && (
                <InfoBanner
                  title="Warning"
                  icon="fa-exclamation-triangle"
                  variant="warning"
                  collapsible={false}
                  summary={
                    <>
                      No fund settlement will be performed: settlement mode is set to{' '}
                      <code>none</code>.
                    </>
                  }
                />
              )}

              {hasAttemptedSave &&
                (config.verification_mode === 'mock' ||
                  config.verification_mode === 'signature') && (
                  <InfoBanner
                    title="Warning"
                    icon="fa-exclamation-triangle"
                    variant="warning"
                    collapsible={false}
                    summary={
                      <>
                        No on-chain verification will be performed: verification mode is{' '}
                        <code>{config.verification_mode}</code>.
                      </>
                    }
                  />
                )}

              <div className="config-section">
                <label>Summary</label>
                <ul
                  className="list-unstyled mb-0 text-muted"
                  style={{ fontSize: '11px', lineHeight: '18px' }}
                >
                  <li>
                    <strong>Verify:</strong> {config.verification_mode || 'mock'}
                  </li>
                  <li>
                    <strong>Settle:</strong> {config.settlement_mode || 'none'}
                  </li>
                  <li>
                    <strong>Networks:</strong> {x402NetworkCount}
                  </li>
                  <li>
                    <strong>Requirements:</strong> {x402ReqCount}
                  </li>
                </ul>
              </div>

              <div className="config-section">
                <button
                  className="btn btn-outline-primary btn-sm w-100"
                  onClick={() => openFullscreenEditor?.()}
                  disabled={!openFullscreenEditor}
                >
                  <i className="fas fa-pen-to-square me-1" /> Configure x402 Paywall…
                </button>
              </div>
            </>
          )}

          {provider !== 'agent_pay' && kind === 'mpp' && (
            <>
              <div className="config-section">
                <label>Realm</label>
                <Form.Control
                  size="sm"
                  type="text"
                  placeholder="example.com"
                  value={config.mpp_realm || ''}
                  onChange={e => updateField('mpp_realm', e.target.value)}
                />
                <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                  Protection space sent on the 402 challenge.
                </Form.Text>
              </div>

              <div className="config-section">
                <MppSecretField
                  label="HMAC Secret Key"
                  value={config.mpp_secret_key || ''}
                  onChange={v => updateField('mpp_secret_key', v)}
                  helpText={
                    <>
                      Base64-encoded HMAC-SHA256 key used for stateless challenge binding. Resolved
                      server-side and never stored in the surface config.
                    </>
                  }
                />
              </div>

              <div className="config-section">
                <label>Challenge TTL (seconds)</label>
                <Form.Control
                  size="sm"
                  type="number"
                  min={1}
                  placeholder="300"
                  value={config.mpp_challenge_ttl ?? ''}
                  onChange={e => updateField('mpp_challenge_ttl', e.target.value)}
                />
              </div>

              <div className="config-section">
                <label>Payment Methods</label>
                {mppMethods.length === 0 ? (
                  <div className="text-muted" style={{ fontSize: '11px' }}>
                    None configured.
                  </div>
                ) : (
                  <ul
                    className="list-unstyled mb-0"
                    style={{ fontSize: '11px', lineHeight: '18px' }}
                  >
                    {mppMethods.map((m, idx) => (
                      <li key={idx}>
                        <code>{m.method || '?'}</code> — {m.currency || '?'} {m.amount || '?'}
                      </li>
                    ))}
                  </ul>
                )}
                <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                  Configured below in "Configure MPP…".
                </Form.Text>
              </div>

              <div className="config-section">
                <label>Summary</label>
                <ul
                  className="list-unstyled mb-0 text-muted"
                  style={{ fontSize: '11px', lineHeight: '18px' }}
                >
                  <li>
                    <strong>Verify:</strong> {config.mpp_crypto_verification_mode || 'passthrough'}
                  </li>
                  <li>
                    <strong>Stripe key:</strong> {config.mpp_stripe_secret_key ? 'set' : 'not set'}
                  </li>
                </ul>
              </div>

              <div className="config-section">
                <button
                  className="btn btn-outline-primary btn-sm w-100"
                  onClick={() => openFullscreenEditor?.()}
                  disabled={!openFullscreenEditor}
                >
                  <i className="fas fa-pen-to-square me-1" /> Configure MPP…
                </button>
                <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                  Payment methods, Stripe card key, on-chain verification mode, and MCP/A2A payment
                  triggers.
                </Form.Text>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
};

export default PaymentPanel;
