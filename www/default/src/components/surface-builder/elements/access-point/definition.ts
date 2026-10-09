import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import { normalizeRoute } from '../validators';
import AccessPointPanel from './AccessPointPanel';
import { DOCS_URL } from '../../../../config/docs';
import { isA2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';
import {
  DEFAULT_A2A_SETTINGS,
  a2aSettingsForPayload,
  isA2aValidation,
  selectedA2aVersions,
} from './a2aSettings';

export const accessPointDefinition: NodeDefinition = {
  type: 'access-point',
  label: 'Access Point',
  description: 'Inbound listener that accepts incoming requests on a route',
  icon: '\uf2f6', // fa-sign-in-alt
  paletteIcon: 'fa-sign-in-alt',
  color: '#2e59d9',
  shape: 'circle',
  defaultRadius: 26,
  resizable: true,
  resizeRange: { min: 18, max: 40 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: true,
  xWeight: 0.15,
  stage: 'ingress',
  cardinality: 'singleton',
  paletteCategory: 'transitPoints',
  paletteOrder: 1,
  dropMode: 'canvas',
  hiddenFromPalette: true, // auto-created with the surface
  deletable: false, // ingress singleton; surface always has exactly one
  provides: [
    Cap.PIPELINE_SOURCE,
    Cap.SURFACE_PERIMETER,
    Cap.MIDDLEWARE_SLOT,
    Cap.POLICY_TARGET,
    Cap.RATE_LIMIT_TARGET,
    Cap.TRUST_REGISTRY_TARGET,
    Cap.EXTENSION_TARGET,
    Cap.METADATA_TARGET,
    Cap.NPC_CONNECTABLE,
    Cap.CONFIGURABLE,
    Cap.ATTACHES_TO_INGRESS,
  ],
  requires: {},
  incompleteReason: config => (!config.route ? 'Route path is required' : null),
  validate: () => [],
  featureDependencies: [
    {
      description: 'An A2A surface accepts at least one A2A version',
      // An A2A proxy Target serves A2A 1.0 whatever is selected, so the
      // disabled checkboxes there never block a save.
      condition: (_config, ctx) =>
        (ctx.protocol === 'a2a' || ctx.protocol === 'ap2') &&
        !isA2aProxyEndpoint(ctx.target?.endpoint),
      check: config => selectedA2aVersions(config).length > 0,
      severity: 'error',
      message: 'Select at least one supported A2A version',
    },
  ],
  help: {
    title: 'Access Point',
    docLink: DOCS_URL.accessPointElement,
    bodyHtml: `
      <p>An Access Point is the inbound "front door" of this agent surface.
      It's what runs first on an incoming request, before anything else in
      the pipeline. Every surface needs exactly one.</p>
      <p>It doesn't own its own network listener. It's configured on top of
      one of the gateway's shared listening addresses, plus the specific
      route/path that identifies this surface at that address. Configure
      which shared address it's reached through, what path callers use, and
      (for A2A surface) how it publishes its agent card, the public
      profile file other systems use to discover and verify this agent.</p>
    `,
  },
  ConfigPanel: AccessPointPanel,
  summary: c => (c?.route ? `${c.listen_address || '0.0.0.0:8443'} ${c.route}` : null),
  getListViewInfo: c => ({
    extras: [c?.listen_address || '0.0.0.0:8443', c?.route || '—'],
  }),
  payloadPath: 'access_point',
  /**
   * Flatten the wire shape back into the flat panel fields.
   */
  configFromPayload: slice => {
    const c: any = { ...slice };
    delete c.caller_context;
    // `trust_check_list` is owned by the separate `trust-check` canvas
    // node — strip it here so a legacy access-point slice carrying the
    // field never seeds it onto the access-point panel's state.
    delete c.trust_check_list;
    if (slice?.identity_resolution && typeof slice.identity_resolution === 'object') {
      const ir = slice.identity_resolution;
      c.identity_resolution = ir.strategy ?? 'from_payload';
      if (ir.static_did) c.static_agent_did = ir.static_did;
      if (ir.claim) c.identity_jwt_claim = ir.claim;
    }
    if (typeof slice?.agent_card_path === 'string' && slice.agent_card_path) {
      c.override_agent_card_location = true;
      c.agent_card_path = slice.agent_card_path;
    }
    if (typeof slice?.primary_extension === 'string') {
      c.primary_extension = slice.primary_extension;
    }
    delete c.header_metadata_mapping;
    if (Array.isArray(slice?.supported_extensions)) {
      c.supported_extensions = slice.supported_extensions.slice();
    }
    // Always set explicitly, so a stale canvas-blob copy cannot reappear on load.
    delete c.a2a;
    if (slice?.protocol === 'a2a' || slice?.protocol === 'ap2') {
      const a2a = slice?.a2a ?? {};
      c.a2a_accepted_versions = Array.isArray(a2a.accepted_versions)
        ? a2a.accepted_versions.slice()
        : [...DEFAULT_A2A_SETTINGS.accepted_versions];
      c.a2a_validation = isA2aValidation(a2a.validation)
        ? a2a.validation
        : DEFAULT_A2A_SETTINGS.validation;
    }
    return c;
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('access-point');
    const c = node?.config ?? {};
    const ap: any = {
      listen_address: c.listen_address || '0.0.0.0:8443',
      route:
        normalizeRoute(c.route) ||
        `/agents/${ctx.surfaceMeta.name.toLowerCase().replace(/\s+/g, '-')}`,
      protocol: ctx.protocol || 'a2a',
    };
    if (c.identity_resolution && c.identity_resolution !== 'from_payload') {
      ap.identity_resolution = {
        strategy: c.identity_resolution,
        ...(c.identity_resolution === 'static' && c.static_agent_did
          ? { static_did: c.static_agent_did }
          : {}),
        ...(c.identity_resolution === 'from_jwt_claims' && c.identity_jwt_claim
          ? { claim: c.identity_jwt_claim }
          : {}),
      };
    }
    if (c.caller_auth) {
      // Legacy AP-level caller-auth fields are now owned by the
      // dedicated Caller Auth canvas element. Silently drop them here
      // so a stale saved config can't re-emit a duplicate slice.
    }
    if (c.didwebvh_enabled) {
      // Backward compat: legacy AP-level didwebvh fields are now owned by
      // the Surface Properties panel's DID Management section; if a saved
      // config still has the old fields we silently drop them here so the
      // new owner can take over without producing a duplicate slice.
    }
    if (
      c.override_agent_card_location &&
      typeof c.agent_card_path === 'string' &&
      c.agent_card_path
    ) {
      ap.agent_card_path = c.agent_card_path;
    }
    if (typeof c.primary_extension === 'string' && c.primary_extension.trim()) {
      ap.primary_extension = c.primary_extension.trim();
    }
    const supportedExtensions = (() => {
      if (Array.isArray(c.supported_extensions)) {
        return c.supported_extensions
          .map((s: unknown) => String(s).trim())
          .filter((s: string) => s.length > 0);
      }
      if (typeof c.supported_extensions === 'string') {
        return c.supported_extensions
          .split(',')
          .map(s => s.trim())
          .filter(s => s.length > 0);
      }
      return [];
    })();
    if (supportedExtensions.length > 0) {
      ap.supported_extensions = supportedExtensions;
    }
    if (typeof c.name === 'string' && c.name.trim()) {
      ap.name = c.name.trim();
    }
    if (ap.protocol === 'a2a' || ap.protocol === 'ap2') {
      const a2a = a2aSettingsForPayload(c, ctx.firstNodeOfType('target')?.config?.endpoint);
      if (a2a) ap.a2a = a2a;
    }
    return [{ path: 'access_point', value: ap }];
  },
};
