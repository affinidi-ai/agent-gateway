import React, { useEffect, useMemo, useState } from 'react';
import { Form } from 'react-bootstrap';
import {
  computeSharedOutboundAddresses,
  fetchRoutingConfig,
  meaningfulListenerAddresses,
  shouldHideListenerPicker,
  type RoutingConfig,
} from '../access-point/defaults';
import { generateRandomPath } from '../../../../utils/stringUtils';
import InfoBanner from '../../../shared/InfoBanner';
import FieldHelp from '../../../shared/FieldHelp';

export interface RouteListenerSectionProps {
  config: any;
  updateField: (field: string, value: any) => void;
  updateFields: (fields: Record<string, any>) => void;
  /**
   * Which list of available addresses to render in the dropdown.
   * APs bind to inbound listeners; TPs bind to the gateway-wide
   * outbound listener.
   */
  addressSource: 'inbound' | 'outbound';
  /**
   * The wire field name this section composes (`<prefix><custom>`).
   * APs write `route`; TPs write `listen_path`.
   */
  routeFieldName: 'route' | 'listen_path';
  /** Banner heading, e.g. "Channel Route" or "Listener URL". */
  bannerLabel: string;
  /**
   * Replace the top history snapshot after the seed runs so undo skips
   * past the auto-seeded defaults. Optional; only APs (auto-created on
   * canvas load) need this. TPs are added by drag and benefit too.
   */
  replaceCommit?: () => void;
  /** Gate path-format errors on this flag so they only appear after a save attempt. */
  hasAttemptedSave?: boolean;
}

const PATH_TRAVERSAL_MSG = 'Path may not contain ".." segments';
const OUTBOUND = '/outbound';

function validatePath(path: string): string | null {
  if (!path) return null;
  if (path.split('/').some(seg => seg === '..')) return PATH_TRAVERSAL_MSG;
  return null;
}

function buildRoutePath(customPath: string): string {
  if (!customPath) return '';
  return customPath.startsWith('/') ? customPath : `/${customPath}`;
}

function translatePrefixForNewAddress({
  selectedPrefix,
  addressSource,
  isSharedDomain,
  newIsShared,
  routingConfig,
}: {
  selectedPrefix: string;
  addressSource: 'inbound' | 'outbound';
  isSharedDomain: boolean;
  newIsShared: boolean;
  routingConfig: RoutingConfig | null;
}): string {
  if (addressSource !== 'outbound' || !selectedPrefix) return selectedPrefix;

  const prefixes = routingConfig?.channel_path_prefix ?? [];

  if (!isSharedDomain && newIsShared) {
    const plain = prefixes.find(c => c.prefix === selectedPrefix);
    if (!plain) return selectedPrefix;
    return `${OUTBOUND}${plain.prefix.replace(/\/$/, '')}`;
  }

  if (isSharedDomain && !newIsShared) {
    if (!selectedPrefix.startsWith(OUTBOUND)) return selectedPrefix;
    const stripped = selectedPrefix.slice(OUTBOUND.length) || '/';
    const match = prefixes.find(c => c.prefix === stripped || c.prefix === `${stripped}/`);
    return match ? match.prefix : selectedPrefix;
  }

  return selectedPrefix;
}

function HostPortOptions({
  routingConfig,
  availableAddresses,
  meaningfulAddresses,
  sharedOutboundAddresses,
}: {
  routingConfig: RoutingConfig | null;
  availableAddresses: string[];
  meaningfulAddresses: string[];
  sharedOutboundAddresses: Set<string>;
}) {
  if (!routingConfig) return <option value="">Loading...</option>;
  if (availableAddresses.length === 0) return <option value="">No addresses available</option>;
  return (
    <>
      <option value="">-- Select listen address --</option>
      {meaningfulAddresses.map(addr => {
        const shared = sharedOutboundAddresses.has(addr);
        return (
          <option key={addr} value={addr}>
            {shared ? `⚠ ${addr} (also on inbound)` : addr}
          </option>
        );
      })}
    </>
  );
}

/**
 * Shared address + prefix + custom-path editor used by Access Points
 * and Transit Points.
 *
 * Persists `route_prefix` + `route_suffix` alongside the composed wire
 * field so the inputs round-trip a saved surface without re-deriving
 * the split (which can drift when the prefix list changes upstream).
 *
 * Auto-seeds a two-word random custom path on first mount when the
 * node has no prior config — matches the AP behaviour callers expect.
 */
const RouteListenerSection: React.FC<RouteListenerSectionProps> = ({
  config,
  updateField,
  updateFields,
  addressSource,
  routeFieldName,
  bannerLabel,
  replaceCommit,
  hasAttemptedSave,
}) => {
  const [routingConfig, setRoutingConfig] = useState<RoutingConfig | null>(null);

  useEffect(() => {
    if (routingConfig) return;
    let alive = true;
    fetchRoutingConfig().then(data => {
      if (alive && data) setRoutingConfig(data);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const availableAddresses: string[] = useMemo(() => {
    if (!routingConfig) return [];
    return addressSource === 'inbound'
      ? routingConfig.available_listen_addresses
      : (routingConfig.available_outbound_listen_addresses ?? []);
  }, [routingConfig, addressSource]);

  // Addresses after stripping localhost entries. If that leaves nothing,
  // fall back to the full list so a localhost-only setup still works.
  const meaningfulAddresses: string[] = useMemo(
    () => meaningfulListenerAddresses(availableAddresses),
    [availableAddresses]
  );

  const selectedHostPort: string = config.listen_address || '';

  // Determine once (when routingConfig first loads) whether to show the
  // Listen Address picker. The decision is locked for the session — once
  // the picker is visible it must stay visible so the user can complete
  // their selection without it vanishing mid-edit.
  const pickerVisibleRef = React.useRef<boolean | null>(null);
  if (routingConfig !== null && pickerVisibleRef.current === null) {
    pickerVisibleRef.current = !shouldHideListenerPicker(meaningfulAddresses, selectedHostPort);
  }
  const hideListenerPicker = pickerVisibleRef.current === true ? false : true;

  // Outbound addresses that are also reachable on an inbound listener (shared domain).
  // Used to label those addresses in the dropdown and to extend the channel-prefix list
  // with /outbound/ options when one is selected.
  const sharedOutboundAddresses: Set<string> = useMemo(
    () =>
      routingConfig && addressSource === 'outbound'
        ? computeSharedOutboundAddresses(routingConfig)
        : new Set(),
    [routingConfig, addressSource]
  );

  const isSharedDomain = selectedHostPort ? sharedOutboundAddresses.has(selectedHostPort) : false;

  const channelPrefixes = useMemo(() => {
    if (!routingConfig) return [];
    if (addressSource !== 'outbound') return routingConfig.channel_path_prefix;
    const plain = routingConfig.channel_path_prefix;
    const outbound = plain.map(c => ({
      id: `outbound-${c.id}`,
      name: `outbound \u2192 ${c.name}`,
      prefix: `${OUTBOUND}${c.prefix.replace(/\/$/, '')}`,
    }));
    // On a shared-domain address the inbound pipeline owns all non-/outbound paths,
    // so only the /outbound/… prefixes are reachable via the outbound pipeline.
    return isSharedDomain ? outbound : plain;
  }, [routingConfig, addressSource, isSharedDomain]);

  const composedRoute: string = config[routeFieldName] || '';

  const { selectedPrefix, customPath } = useMemo(() => {
    if (config.route_prefix || config.route_suffix !== undefined) {
      return {
        selectedPrefix: config.route_prefix || '',
        customPath: config.route_suffix || '',
      };
    }
    if (!composedRoute || !routingConfig) {
      return { selectedPrefix: '', customPath: '' };
    }
    const match = channelPrefixes.find(
      p => composedRoute === p.prefix || composedRoute.startsWith(p.prefix + '/')
    );
    if (!match) return { selectedPrefix: '', customPath: composedRoute };
    const suffix = composedRoute.substring(match.prefix.length);
    return {
      selectedPrefix: match.prefix,
      customPath: suffix.startsWith('/') ? suffix.substring(1) : suffix,
    };
  }, [config.route_prefix, config.route_suffix, composedRoute, routingConfig, channelPrefixes]);

  // First-time seed: drop a two-word default + first available address +
  // first prefix into a brand-new node. Subsequent mounts (undo / redo,
  // restored surface) skip seeding because at least one of the route
  // fields is already populated.
  const seededRef = React.useRef(false);
  useEffect(() => {
    if (seededRef.current) return;
    if (!routingConfig) return;

    if (composedRoute || config.route_suffix) {
      seededRef.current = true;
      // Backfill missing pieces if a prior partial seed left them blank.
      const patch: Record<string, any> = {};
      if (!config.listen_address && availableAddresses[0]) {
        patch.listen_address = meaningfulAddresses[0] ?? availableAddresses[0];
      }
      if (!config.route_prefix && routingConfig.channel_path_prefix[0]) {
        const matched = routingConfig.channel_path_prefix.find(
          p => composedRoute === p.prefix || composedRoute.startsWith(p.prefix + '/')
        );
        const prefix = matched?.prefix ?? routingConfig.channel_path_prefix[0].prefix;
        const derivedSuffix = matched ? composedRoute.substring(matched.prefix.length) : '';
        const suffix = config.route_suffix || derivedSuffix || '';
        const path = suffix ? (suffix.startsWith('/') ? suffix : `/${suffix}`) : '';
        patch.route_prefix = prefix;
        if (suffix) {
          patch.route_suffix = suffix.startsWith('/') ? suffix.substring(1) : suffix;
        }
        if (path) patch[routeFieldName] = `${prefix}${path}`;
      }
      if (Object.keys(patch).length > 0) updateFields(patch);
      return;
    }

    seededRef.current = true;
    const suffix = generateRandomPath();
    const path = suffix.startsWith('/') ? suffix : `/${suffix}`;
    const prefix = routingConfig.channel_path_prefix[0]?.prefix ?? '';
    const listen = meaningfulAddresses[0] ?? availableAddresses[0] ?? '';
    updateFields({
      listen_address: listen,
      route_prefix: prefix,
      route_suffix: suffix,
      [routeFieldName]: prefix && path ? `${prefix}${path}` : '',
    });
    replaceCommit?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routingConfig]);

  const writeRouteParts = (prefix: string, suffix: string) => {
    const trimmed = suffix.trim();
    const path = trimmed ? (trimmed.startsWith('/') ? trimmed : `/${trimmed}`) : '';
    const composed = prefix && path ? `${prefix}${path}` : '';
    updateFields({
      route_prefix: prefix,
      route_suffix: suffix,
      [routeFieldName]: composed,
    });
  };

  const pathError = useMemo(() => validatePath(customPath), [customPath]);

  const fullRouteDisplay = useMemo(() => {
    if (!selectedHostPort || !selectedPrefix) return '';
    const suffix = customPath.startsWith('/') ? customPath : `/${customPath}`;
    return `${selectedHostPort}${selectedPrefix}${suffix}`;
  }, [selectedHostPort, selectedPrefix, customPath]);

  const handleHostPortChange = (newAddr: string) => {
    const newIsShared = sharedOutboundAddresses.has(newAddr);
    const newPrefix = translatePrefixForNewAddress({
      selectedPrefix,
      addressSource,
      isSharedDomain,
      newIsShared,
      routingConfig,
    });
    if (newPrefix === selectedPrefix) {
      updateField('listen_address', newAddr);
      return;
    }
    const path = buildRoutePath(customPath);
    updateFields({
      listen_address: newAddr,
      route_prefix: newPrefix,
      [routeFieldName]: newPrefix && path ? `${newPrefix}${path}` : newPrefix,
    });
  };

  // This section renders for two different directions with two different
  // audiences: an Access Point's address is what *other agents* call in on
  // (inbound); a Transit Point's is what *your own Managed Agent* calls out
  // through to start an outbound request — never something other agents
  // reach this surface at. Keep the copy specific to which one this is.
  const isOutboundListener = addressSource === 'outbound';
  const routingIntro = isOutboundListener ? (
    <>
      This is the network address and path your Managed Agent calls to start an outbound request
      through this Transit Point, not an address other agents use to reach this surface. The gateway
      auto-fills a random path so you can save immediately, but you can change it to something
      memorable if you need to reference it directly.
    </>
  ) : (
    <>
      This is the network address and path other agents will use to reach this surface. The gateway
      auto-fills a random path so you can save immediately, but you can change it to something
      memorable before sharing the URL.
    </>
  );
  const listenAddressHelp = isOutboundListener ? (
    <>
      <p>
        Choose which address the gateway should listen on for this Transit Point. Your Managed Agent
        calls this address to start an outbound request; it's not an address other agents use to
        reach this surface.
      </p>
      <p>
        Most setups only have one address, so this gets filled in automatically. If there are
        several (e.g. public vs. internal), pick the one your Managed Agent's configuration actually
        points at.
      </p>
    </>
  ) : (
    <>
      <p>
        Choose which address the gateway should listen on for incoming calls to this agent, the
        "front door" this agent answers at.
      </p>
      <p>
        Most setups only have one address, so this gets filled in automatically. If there are
        several (e.g. public vs. internal), pick the one your callers will actually connect to.
      </p>
    </>
  );

  return (
    <>
      <RouteListenerBanner
        label={bannerLabel}
        url={fullRouteDisplay}
        warning={pathError ?? undefined}
      />

      <div className="config-section">
        <label>Routing</label>
        <InfoBanner className="mb-2" title="How routing works" summary={routingIntro} />
        {!hideListenerPicker && addressSource === 'outbound' && isSharedDomain && (
          <InfoBanner
            className="mb-2"
            collapsible={false}
            summary={
              <>
                This address is shared with <strong>Access Point</strong> routing - the{' '}
                <code>{OUTBOUND}/…</code> path prefix ensures correct routing for{' '}
                <strong>Transit Point</strong>.
              </>
            }
          />
        )}
        {!hideListenerPicker && (
          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-1">
              <Form.Label className="small text-muted mb-0">
                Listen Address (Host:Port) <span className="text-danger">*</span>
              </Form.Label>
              <FieldHelp
                testId="field-help-route-listener-section-listen-address"
                ariaLabel="About Listen Address"
              >
                {listenAddressHelp}
              </FieldHelp>
            </div>
            <Form.Select
              size="sm"
              value={selectedHostPort}
              onChange={e => handleHostPortChange(e.target.value)}
              disabled={!routingConfig || availableAddresses.length === 0}
            >
              <HostPortOptions
                routingConfig={routingConfig}
                availableAddresses={availableAddresses}
                meaningfulAddresses={meaningfulAddresses}
                sharedOutboundAddresses={sharedOutboundAddresses}
              />
            </Form.Select>
          </Form.Group>
        )}
        <label className="mt-2">Listen Path</label>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">
              Surface Prefix <span className="text-danger">*</span>
            </Form.Label>
            <FieldHelp
              testId="field-help-route-listener-section-surface-prefix"
              ariaLabel="About Surface Prefix"
            >
              <p>
                Pick the base part of this agent's web address, before your own custom path, like
                choosing which shared folder on the gateway your agent's URL lives under.
              </p>
              <p>
                This groups the route under one of the gateway's shared entry paths; pick the one
                your network/firewall setup already routes to this gateway.
              </p>
              <p>This list comes from this gateway's own deployment configuration.</p>
            </FieldHelp>
          </div>
          <Form.Select
            size="sm"
            value={selectedPrefix}
            onChange={e => writeRouteParts(e.target.value, customPath)}
            disabled={!routingConfig || channelPrefixes.length === 0}
          >
            {!routingConfig ? (
              <option value="">Loading...</option>
            ) : channelPrefixes.length === 0 ? (
              <option value="">No prefixes available</option>
            ) : (
              <>
                <option value="">-- Select prefix --</option>
                {channelPrefixes.map(item => (
                  <option key={item.id} value={item.prefix}>
                    {item.name}
                  </option>
                ))}
              </>
            )}
          </Form.Select>
        </Form.Group>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">
              Custom Path <span className="text-danger">*</span>
            </Form.Label>
            <FieldHelp
              testId="field-help-route-listener-section-custom-path"
              ariaLabel="About Custom Path"
            >
              This is the last part of your agent's web address, the bit that makes it unique (e.g.{' '}
              <code>my-agent/v1</code>). Keep it short and avoid <code>..</code>.
            </FieldHelp>
          </div>
          <Form.Control
            size="sm"
            type="text"
            placeholder="my-agent/v1"
            value={customPath.startsWith('/') ? customPath.substring(1) : customPath}
            isInvalid={!!hasAttemptedSave && !!pathError}
            onChange={e => writeRouteParts(selectedPrefix, e.target.value)}
          />
          {!!hasAttemptedSave && pathError && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              {pathError}
            </Form.Control.Feedback>
          )}
          <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
            Once saved, this becomes a real URL other systems call. Avoid changing it later without
            telling anyone who already points at it.
          </Form.Text>
        </Form.Group>
      </div>
    </>
  );
};

export default RouteListenerSection;

export interface RouteListenerBannerProps {
  /** Heading text shown in bold before the URL. */
  label: string;
  /** Composed URL to display. Empty string renders the placeholder hint. */
  url: string;
  /** When set, the banner switches to warning style and shows this message instead of the URL. */
  warning?: string;
  /** Placeholder text when `url` is empty and there's no warning. */
  placeholder?: string;
}

/**
 * Read-only banner used by `RouteListenerSection` and by panels that
 * want to surface another node's listener URL (e.g. a Managed Agent
 * showing the Access Point's URL as a convenience). Identical look,
 * feel, and copy behaviour as the editing variant.
 */
export const RouteListenerBanner: React.FC<RouteListenerBannerProps> = ({
  label,
  url,
  warning,
  placeholder = '(select address and prefix)',
}) => {
  const hasUrl = !!url && !warning;
  const display = warning ? warning : url || placeholder;
  return (
    <div
      className={`alert ${warning ? 'alert-warning' : 'alert-success'} mb-3`}
      style={{ fontSize: '13px' }}
    >
      <i className="fas fa-info-circle me-2"></i>
      <strong>{label}:</strong> {display}
      {hasUrl && (
        <button
          type="button"
          className="btn btn-xs ms-2"
          style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
          onClick={e => {
            navigator.clipboard.writeText(url);
            const btn = e.currentTarget as HTMLButtonElement;
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
              btn.innerHTML = originalHtml;
            }, 2000);
          }}
          title="Copy to clipboard"
        >
          <i className="fas fa-copy"></i>
        </button>
      )}
    </div>
  );
};
