import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../../../api';
import FieldHelp from '../../../shared/FieldHelp';
import type { ConfigPanelProps } from '../types';
import PaymentManifestPreview from './PaymentManifestPreview';
import { usePaymentManifest } from './usePaymentManifest';
import { describeTriggers } from './triggers';
import {
  DISABLED_LEGACY_PAYMENT_MESSAGE,
  LEGACY_PAYMENT_MESSAGE,
  PAYMENT_TIMEOUT_DEFAULT_MS,
  PAYMENT_TIMEOUT_MAX_MS,
  PAYMENT_TIMEOUT_MESSAGE,
  PAYMENT_TIMEOUT_MIN_MS,
  PAYMENT_TIMEOUT_SHORT_MESSAGE,
  isTimeoutShort,
  isTimeoutValid,
  keepsPreservedPolicy,
  migrateLegacyPaymentConfig,
} from './policy';
import type { PaymentNodeConfig } from './types';

interface DiscoveredSurface {
  config_id: string;
  name: string;
  tags: string[];
  is_payment_surface: boolean | null;
  has_manifest: boolean;
}

interface GatewayRecord {
  id: string;
  name?: string;
  gateway_type?: string;
  creation_type?: string;
}

interface SurfaceRecord {
  config_id: string;
  name?: string;
  tags?: unknown;
  is_payment_surface?: unknown;
  payment_manifest?: unknown;
}

type SurfaceListResponse = SurfaceRecord[] | { channels?: SurfaceRecord[] };

const isPaymentCandidate = (s: DiscoveredSurface) =>
  s.is_payment_surface === true || s.has_manifest || s.tags.includes('payment');

const LegacyPaymentBanner: React.FC<{ kind: string; onMigrate: () => void }> = ({
  kind,
  onMigrate,
}) => (
  <div
    className="config-section surface-info-panel surface-info-panel--danger"
    role="alert"
    data-testid="payment-legacy-unsupported-banner"
  >
    <div className="surface-info-panel-title">
      <i className="fas fa-ban me-1" aria-hidden="true" />
      Local {kind === 'mpp' ? 'MPP' : 'x402'} payment
    </div>
    <div className="surface-info-panel-summary">{LEGACY_PAYMENT_MESSAGE}</div>
    <button
      type="button"
      className="btn btn-outline-primary btn-sm w-100 mt-2"
      onClick={onMigrate}
      data-testid="payment-legacy-migrate-button"
    >
      <i className="fas fa-arrow-right-arrow-left me-1" aria-hidden="true" /> Start migration
    </button>
    <div className="text-muted mt-1" style={{ fontSize: '10px' }}>
      Clears the local payment settings and keeps the MCP/A2A triggers.
    </div>
  </div>
);

const PaymentPanel: React.FC<ConfigPanelProps> = ({
  config: panelConfig,
  updateField,
  updateFields,
  protocol,
  openFullscreenEditor,
}) => {
  const config: PaymentNodeConfig = panelConfig;
  const isPaymentSupported = protocol === 'mcp' || protocol === 'a2a';
  const legacy = config.unsupported_legacy;
  const active = isPaymentSupported && !legacy;
  const navigate = useNavigate();
  const selectedGatewayId = config.payment_gateway_id || '';
  const selectedSurfaceId = config.payment_surface_id || '';

  const [peerGateways, setPeerGateways] = useState<Array<{ id: string; name?: string }>>([]);
  const [gatewaysLoaded, setGatewaysLoaded] = useState(false);
  const [surfaces, setSurfaces] = useState<DiscoveredSurface[]>([]);
  const [surfacesLoading, setSurfacesLoading] = useState(false);
  const [surfacesError, setSurfacesError] = useState<string | null>(null);
  const [surfacesRefreshTick, setSurfacesRefreshTick] = useState(0);
  const [manualEntry, setManualEntry] = useState(false);
  const [paymentOnly, setPaymentOnly] = useState(true);
  const [paymentGatewayIds, setPaymentGatewayIds] = useState<Set<string> | null>(null);

  const manifest = usePaymentManifest(
    selectedGatewayId,
    selectedSurfaceId.trim(),
    config.manifest_snapshot
  );

  // A saved snapshot describes the saved selection, so choosing another gateway or surface drops it.
  // A surface id only means something on its own gateway, so another gateway clears it too.
  const selectGateway = (value: string) => {
    if (value === selectedGatewayId) return;
    setManualEntry(false);
    updateFields({
      payment_gateway_id: value,
      payment_surface_id: undefined,
      manifest_snapshot: undefined,
    });
  };
  const selectSurface = (value: string) =>
    updateFields({ payment_surface_id: value, manifest_snapshot: undefined });

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    apiClient
      .get<GatewayRecord[]>('/gateways')
      .then(({ data }) => {
        if (cancelled) return;
        const remotes = (data || []).filter(
          gw => gw.gateway_type === 'remote' && gw.creation_type === 'user'
        );
        setPeerGateways(remotes.map(gw => ({ id: gw.id, name: gw.name })));
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
  }, [active]);

  useEffect(() => {
    if (!active || !selectedGatewayId) {
      setSurfaces([]);
      setSurfacesError(null);
      return;
    }
    let cancelled = false;
    setSurfacesLoading(true);
    setSurfacesError(null);
    const force = surfacesRefreshTick > 0 ? '?force_refresh=true' : '';
    apiClient
      .get<SurfaceListResponse>(
        `/gateways/${encodeURIComponent(selectedGatewayId)}/surfaces${force}`
      )
      .then(({ data }) => {
        if (cancelled) return;
        const list = Array.isArray(data) ? data : data?.channels || [];
        setSurfaces(
          list.map(c => ({
            config_id: c.config_id,
            name: c.name || c.config_id,
            tags: Array.isArray(c.tags) ? c.tags : [],
            is_payment_surface:
              typeof c.is_payment_surface === 'boolean' ? c.is_payment_surface : null,
            has_manifest: !!c.payment_manifest,
          }))
        );
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setSurfaces([]);
        const msg = err instanceof Error && err.message ? err.message : String(err);
        setSurfacesError(
          msg.toLowerCase().includes('not connected') || msg.includes('503')
            ? 'Gateway not connected, cannot list its payment surfaces. Enter the surface id manually, or retry once it reconnects.'
            : `Could not load surfaces: ${msg}`
        );
      })
      .finally(() => {
        if (!cancelled) setSurfacesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [active, selectedGatewayId, surfacesRefreshTick]);

  // A peer that predates the payment markers sends none on any surface; the
  // payment-only filter is then a no-op so discovery still works.
  const peerSupportsPaymentFilter = useMemo(
    () =>
      surfaces.some(
        s =>
          (s.is_payment_surface !== null && s.is_payment_surface !== undefined) ||
          s.has_manifest ||
          s.tags.length > 0
      ),
    [surfaces]
  );
  const visibleSurfaces = useMemo(
    () =>
      paymentOnly && peerSupportsPaymentFilter ? surfaces.filter(isPaymentCandidate) : surfaces,
    [paymentOnly, peerSupportsPaymentFilter, surfaces]
  );

  // A stale discovery cache can predate the peer's payment markers; refresh
  // once per gateway so the picker can see them.
  const autoRefreshedGatewayRef = useRef<string | null>(null);
  useEffect(() => {
    if (!active || !selectedGatewayId) return;
    if (surfacesLoading || surfaces.length === 0) return;
    if (!paymentOnly || peerSupportsPaymentFilter) return;
    if (autoRefreshedGatewayRef.current === selectedGatewayId) return;
    autoRefreshedGatewayRef.current = selectedGatewayId;
    setSurfacesRefreshTick(t => t + 1);
  }, [
    active,
    selectedGatewayId,
    surfacesLoading,
    surfaces,
    paymentOnly,
    peerSupportsPaymentFilter,
  ]);

  useEffect(() => {
    if (!active || !paymentOnly) {
      setPaymentGatewayIds(null);
      return;
    }
    let cancelled = false;
    apiClient
      .get<Array<{ id: string }>>('/gateways/payment-providers')
      .then(({ data }) => {
        if (!cancelled) setPaymentGatewayIds(new Set((data || []).map(g => g.id)));
      })
      .catch(() => {
        if (!cancelled) setPaymentGatewayIds(null);
      });
    return () => {
      cancelled = true;
    };
  }, [active, paymentOnly]);

  const visibleGateways = useMemo(() => {
    if (!paymentOnly || !paymentGatewayIds || paymentGatewayIds.size === 0) return peerGateways;
    return peerGateways.filter(gw => paymentGatewayIds.has(gw.id) || gw.id === selectedGatewayId);
  }, [peerGateways, paymentGatewayIds, paymentOnly, selectedGatewayId]);

  const timeoutValid = isTimeoutValid(config.timeout_ms);
  const selectedBase = selectedSurfaceId.split('$')[0];
  const selectedListed = visibleSurfaces.some(s => s.config_id === selectedSurfaceId);

  if (!isPaymentSupported) {
    return (
      <div className="config-section">
        <div className="alert alert-info py-2 mb-0" style={{ fontSize: '11px' }}>
          <i className="fas fa-info-circle me-1" aria-hidden="true" /> Payment requires MCP or A2A
          protocol.
        </div>
      </div>
    );
  }

  if (legacy) {
    return (
      <LegacyPaymentBanner
        kind={legacy}
        onMigrate={() =>
          updateFields({
            unsupported_legacy: undefined,
            original: undefined,
            ...migrateLegacyPaymentConfig(config),
          })
        }
      />
    );
  }

  return (
    <>
      {keepsPreservedPolicy(config) && (
        <div
          className="config-section surface-info-panel"
          data-testid="payment-disabled-legacy-note"
        >
          <div className="surface-info-panel-title">
            <i className="fas fa-circle-pause me-1" aria-hidden="true" />
            Disabled payment policy
          </div>
          <div className="surface-info-panel-summary">{DISABLED_LEGACY_PAYMENT_MESSAGE}</div>
        </div>
      )}
      {gatewaysLoaded && peerGateways.length === 0 && (
        <div className="config-section surface-info-panel surface-info-panel--warning">
          <div className="surface-info-panel-title">
            <i className="fas fa-plug me-1" aria-hidden="true" />
            No connected gateway
          </div>
          <div className="surface-info-panel-summary">
            There is no connected gateway to take payments. Connect an agent-pay gateway first, then
            select it here.
          </div>
          <button
            type="button"
            className="btn btn-outline-primary btn-sm w-100 mt-2"
            onClick={() => navigate('/gateways/connect')}
            data-testid="payment-connect-gateway-button"
          >
            <i className="fas fa-link me-1" aria-hidden="true" /> Connect a gateway…
          </button>
        </div>
      )}

      {peerGateways.length > 0 && (
        <div className="config-section">
          <label htmlFor="payment-gateway-select">Payment Gateway</label>
          <Form.Check
            type="switch"
            id="payment-only-filter-toggle"
            data-testid="payment-only-filter-toggle"
            className="mt-1 mb-1"
            style={{ fontSize: '11px' }}
            checked={paymentOnly}
            onChange={e => setPaymentOnly(e.target.checked)}
            label="Only payment connection points"
          />
          <Form.Select
            id="payment-gateway-select"
            size="sm"
            data-testid="payment-gateway-select"
            value={selectedGatewayId}
            onChange={e => selectGateway(e.target.value)}
          >
            <option value="">Select a connected gateway…</option>
            {visibleGateways.map(gw => (
              <option key={gw.id} value={gw.id}>
                {gw.name || gw.id}
              </option>
            ))}
          </Form.Select>
          {paymentOnly &&
            !!paymentGatewayIds &&
            paymentGatewayIds.size > 0 &&
            visibleGateways.length < peerGateways.length && (
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                Showing only gateways that expose a payment surface. Turn off the filter to see all{' '}
                {peerGateways.length}.
              </Form.Text>
            )}
        </div>
      )}

      {selectedGatewayId && (
        <div className="config-section">
          <div className="d-flex justify-content-between align-items-center">
            <label className="mb-0" htmlFor="payment-surface-select">
              Payment Surface
            </label>
            <button
              type="button"
              className="btn btn-link btn-sm p-0"
              style={{ fontSize: '10px' }}
              onClick={() => setSurfacesRefreshTick(t => t + 1)}
              disabled={surfacesLoading}
              data-testid="payment-surface-refresh-button"
            >
              <i className="fas fa-rotate me-1" aria-hidden="true" />
              {surfacesLoading ? 'Loading…' : 'Refresh'}
            </button>
          </div>

          <Form.Select
            id="payment-surface-select"
            size="sm"
            data-testid="payment-surface-select"
            value={selectedSurfaceId}
            onChange={e => selectSurface(e.target.value)}
            disabled={surfacesLoading}
          >
            <option value="">
              {surfacesLoading ? 'Loading…' : 'Select an exposed payment surface…'}
            </option>
            {selectedSurfaceId && !selectedListed && (
              <option value={selectedSurfaceId}>
                {selectedSurfaceId}{' '}
                {visibleSurfaces.some(s => s.config_id === selectedBase)
                  ? '(variant)'
                  : '(not currently exposed)'}
              </option>
            )}
            {visibleSurfaces.map(s => (
              <option key={s.config_id} value={s.config_id}>
                {s.name && s.name !== s.config_id
                  ? `${s.name} (${s.config_id.slice(0, 8)}…)`
                  : s.config_id}
              </option>
            ))}
          </Form.Select>

          {surfacesError ? (
            <Form.Text className="text-warning d-block" style={{ fontSize: '10px' }}>
              <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
              {surfacesError}
            </Form.Text>
          ) : visibleSurfaces.length === 0 && !surfacesLoading ? (
            <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
              {surfaces.length > 0 && paymentOnly && peerSupportsPaymentFilter
                ? 'No payment surfaces found on this gateway. Expose a payment surface (or a surface on a connection point tagged “payment”) in agent-pay and press Refresh, or turn off the filter above to see all surfaces.'
                : 'No exposed surfaces discovered. Expose the payment surface on the agent-pay gateway, then Refresh.'}
            </Form.Text>
          ) : null}

          {!surfacesLoading && (
            <button
              type="button"
              className="btn btn-link btn-sm p-0"
              style={{ fontSize: '10px' }}
              onClick={() => setManualEntry(m => !m)}
              data-testid="payment-surface-manual-toggle-button"
            >
              {manualEntry ? 'Hide manual entry' : 'Enter surface id manually'}
            </button>
          )}

          {manualEntry && (
            <>
              <Form.Control
                className="mt-1"
                size="sm"
                type="text"
                aria-label="Payment surface id"
                placeholder="surface-id or surface-id$alias"
                data-testid="payment-surface-manual-input"
                value={selectedSurfaceId}
                onChange={e => selectSurface(e.target.value)}
              />
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                Add <code>$alias</code> to charge through one of the surface&apos;s variants.
              </Form.Text>
            </>
          )}
        </div>
      )}

      {selectedGatewayId && selectedSurfaceId.trim() && (
        <PaymentManifestPreview
          manifest={manifest.manifest}
          source={manifest.source}
          loading={manifest.loading}
          error={manifest.error}
          drift={manifest.drift}
          onRefresh={manifest.refresh}
        />
      )}

      <div className="config-section">
        <label>Triggers</label>
        <div
          className="text-muted mb-1"
          style={{ fontSize: '11px' }}
          data-testid="payment-triggers-summary"
        >
          {describeTriggers(config, protocol)}
        </div>
        <button
          type="button"
          className="btn btn-outline-primary btn-sm w-100"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
          data-testid="payment-configure-triggers-button"
        >
          <i className="fas fa-pen-to-square me-1" aria-hidden="true" /> Configure triggers…
        </button>
      </div>

      <div className="config-section">
        <Form.Check
          type="switch"
          id="payment-require-all-toggle"
          data-testid="payment-require-all-toggle"
          style={{ fontSize: '11px' }}
          checked={config.require_all === true}
          onChange={e => updateField('require_all', e.target.checked)}
          label="Charge every request"
        />
        <div className="d-flex align-items-center gap-1">
          <Form.Check
            type="switch"
            id="payment-share-email-toggle"
            data-testid="payment-share-email-toggle"
            style={{ fontSize: '11px' }}
            checked={config.share_payer_email === true}
            onChange={e => updateField('share_payer_email', e.target.checked)}
            label="Share the payer's email with agent-pay"
          />
          <FieldHelp ariaLabel="About sharing the payer email" testId="payment-share-email-help">
            <p className="mb-0">
              Off by default. When on, the caller&apos;s email from source authentication is sent to
              agent-pay with each payment. agent-pay stores a pseudonymous reference rather than the
              address, but the address still leaves this gateway. An email address is personal data:
              turn this on only when agent-pay needs it and your privacy notice covers sharing it.
            </p>
          </FieldHelp>
        </div>
      </div>

      <div className="config-section">
        <label htmlFor="payment-timeout-input">Timeout (ms)</label>
        <Form.Control
          id="payment-timeout-input"
          size="sm"
          type="number"
          min={PAYMENT_TIMEOUT_MIN_MS}
          max={PAYMENT_TIMEOUT_MAX_MS}
          step={1}
          placeholder={String(PAYMENT_TIMEOUT_DEFAULT_MS)}
          data-testid="payment-timeout-input"
          isInvalid={!timeoutValid}
          aria-describedby="payment-timeout-help"
          value={config.timeout_ms ?? ''}
          onChange={e =>
            updateField('timeout_ms', e.target.value === '' ? undefined : Number(e.target.value))
          }
        />
        <Form.Text
          id="payment-timeout-help"
          className="text-muted d-block"
          style={{ fontSize: '10px' }}
        >
          How long to wait for agent-pay, {PAYMENT_TIMEOUT_MIN_MS} to {PAYMENT_TIMEOUT_MAX_MS} ms.
          Empty means {PAYMENT_TIMEOUT_DEFAULT_MS} ms.
        </Form.Text>
        {!timeoutValid && (
          <Form.Text
            className="text-danger d-block"
            style={{ fontSize: '10px' }}
            role="alert"
            data-testid="payment-timeout-error"
          >
            {PAYMENT_TIMEOUT_MESSAGE}
          </Form.Text>
        )}
        {isTimeoutShort(config.timeout_ms) && (
          <Form.Text
            className="text-warning d-block"
            style={{ fontSize: '10px' }}
            data-testid="payment-timeout-warning"
          >
            {PAYMENT_TIMEOUT_SHORT_MESSAGE}
          </Form.Text>
        )}
      </div>
    </>
  );
};

export default PaymentPanel;
