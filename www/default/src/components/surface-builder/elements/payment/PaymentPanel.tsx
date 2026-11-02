import React, { useEffect, useMemo, useRef } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';
import { deepLinks } from '../../../../utils/deepLinks';
import GatewaySurfacePicker from '../_shared/GatewaySurfacePicker';
import {
  useGatewaySurfaces,
  type GatewayOption,
  type RemoteSurface,
} from '../_shared/useGatewaySurfaces';
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

/** The connected agent-pay gateways that expose at least one payment surface. */
async function loadPaymentGateways(force: boolean): Promise<GatewayOption[]> {
  const { data } = await apiClient.get<Array<{ id: string; name?: string }>>(
    `/gateways/payment-providers${force ? '?force_refresh=true' : ''}`
  );
  return (Array.isArray(data) ? data : []).map(gw => ({ id: gw.id, name: gw.name }));
}

const isPaymentCandidate = (s: RemoteSurface) =>
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
  const selectedGatewayId = config.payment_gateway_id || '';
  const selectedSurfaceId = config.payment_surface_id || '';

  const gatewayState = useGatewaySurfaces({
    enabled: active,
    gatewayId: selectedGatewayId,
    loadGateways: loadPaymentGateways,
    surfacesBasePath: '/payment-gateways',
  });
  const { surfaces, surfacesLoading, refreshSurfaces } = gatewayState;

  const manifest = usePaymentManifest(
    selectedGatewayId,
    selectedSurfaceId.trim(),
    config.manifest_snapshot
  );

  // A saved snapshot describes the saved selection, so choosing another gateway or surface drops it.
  // A surface id only means something on its own gateway, so another gateway clears it too.
  const selectGateway = (value: string) => {
    if (value === selectedGatewayId) return;
    updateFields({
      payment_gateway_id: value,
      payment_surface_id: undefined,
      manifest_snapshot: undefined,
    });
  };
  const selectSurface = (value: string) =>
    updateFields({ payment_surface_id: value, manifest_snapshot: undefined });

  // A peer that predates the payment markers sends none on any surface; the
  // payment filter then keeps every surface so discovery still works.
  const peerSupportsPaymentFilter = useMemo(
    () => surfaces.some(s => s.is_payment_surface !== null || s.has_manifest || s.tags.length > 0),
    [surfaces]
  );
  const visibleSurfaces = useMemo(
    () => (peerSupportsPaymentFilter ? surfaces.filter(isPaymentCandidate) : surfaces),
    [peerSupportsPaymentFilter, surfaces]
  );

  // A stale discovery cache can predate the peer's payment markers; refresh
  // once per gateway so the picker can see them.
  const autoRefreshedGatewayRef = useRef<string | null>(null);
  useEffect(() => {
    if (!active || !selectedGatewayId) return;
    if (surfacesLoading || surfaces.length === 0 || peerSupportsPaymentFilter) return;
    if (autoRefreshedGatewayRef.current === selectedGatewayId) return;
    autoRefreshedGatewayRef.current = selectedGatewayId;
    refreshSurfaces();
  }, [
    active,
    selectedGatewayId,
    surfacesLoading,
    surfaces,
    peerSupportsPaymentFilter,
    refreshSurfaces,
  ]);

  const timeoutValid = isTimeoutValid(config.timeout_ms);
  const savedSurfaceLabel = (id: string) =>
    `${id} ${visibleSurfaces.some(s => s.config_id === id.split('$')[0]) ? '(variant)' : '(not currently exposed)'}`;

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

      <div className="config-section">
        <GatewaySurfacePicker
          testIdPrefix="payment"
          state={gatewayState}
          gatewayId={selectedGatewayId}
          surfaceId={selectedSurfaceId}
          surfaces={visibleSurfaces}
          onGatewayChange={selectGateway}
          onSurfaceChange={selectSurface}
          gatewayLabel="Payment Gateway"
          gatewayPlaceholder="Select a payment gateway…"
          gatewayHelp={
            <p className="mb-0">
              The active payment gateways (Connections → Payment Gateways) that expose at least one
              payment surface. Payments for this surface are taken by the gateway you pick.
            </p>
          }
          noGatewayTitle="No connected payment gateway"
          noGatewayText="Connect an agent-pay payment gateway that exposes a payment surface, then select it here."
          addGatewayLink={deepLinks.paymentGateway}
          addGatewayLabel="Add Payment Gateway"
          surfaceLabel="Payment Surface"
          surfacePlaceholder="Select a payment surface…"
          surfaceHelp={
            <p className="mb-0">
              The payment surfaces this gateway exposes: a surface with a payment manifest, or one
              on a connection point tagged “payment”. Refresh loads the list again.
            </p>
          }
          emptySurfacesText="No exposed surfaces discovered. Expose the payment surface on the agent-pay gateway, then Refresh."
          hiddenSurfacesText="No payment surfaces found on this gateway. Expose a payment surface (or a surface on a connection point tagged “payment”) in agent-pay, then Refresh."
          savedSurfaceLabel={savedSurfaceLabel}
        />
      </div>

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
