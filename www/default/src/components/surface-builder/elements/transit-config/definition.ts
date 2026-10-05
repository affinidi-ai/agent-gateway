import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import TransitConfigPanel from './TransitConfigPanel';

/**
 * Flatten the persisted `transit.*` shared fields back into the panel's
 * flat form-state shape. Mirrors the projection in `buildPayload` below
 * so a surface JSON-edited outside the UI still hydrates the panel
 * fields when the user opens the surface editor.
 *
 * Returns `null` when no shared transit field is set (caller decides
 * whether to materialise a transit-config node at all).
 */
export function transitConfigConfigFromPayload(payload: any): Record<string, any> | null {
  const t = payload?.transit;
  if (!t || typeof t !== 'object') return null;
  const c: Record<string, any> = {};
  let any = false;
  if (typeof t.outbound_listen_address === 'string' && t.outbound_listen_address) {
    c.outbound_listen_address = t.outbound_listen_address;
    any = true;
  }
  if (t.transit_token_mode) {
    c.transit_token_mode = t.transit_token_mode;
  } else {
    c.transit_token_mode = 'embedded';
  }
  if (t.sign_requests !== undefined) {
    c.sign_requests = !!t.sign_requests;
  } else {
    c.sign_requests = true;
  }
  if (t.transit_policy?.policy_definition_id) {
    c.transit_policy_definition_id = t.transit_policy.policy_definition_id;
    any = true;
  }
  if (typeof t.opa_policy_definition_id === 'string' && t.opa_policy_definition_id) {
    c.opa_policy_definition_id = t.opa_policy_definition_id;
    any = true;
  }
  if (t.rate_limit && typeof t.rate_limit === 'object' && t.rate_limit.requests != null) {
    c.rate_limit_requests = String(t.rate_limit.requests);
    c.rate_limit_window_secs = String(t.rate_limit.window_secs ?? 60);
    any = true;
  }
  // Reverse of the listener_auth_type → transit.source_auth projection.
  const sa = t.source_auth;
  if (sa && typeof sa === 'object' && sa.type) {
    if (sa.type === 'api_key') {
      c.listener_auth_type = 'api_key';
      c.listener_auth_header = sa.extraction?.field || 'X-API-Key';
      c.listener_auth_secret_id = sa.secret_id || '';
      any = true;
    } else if (sa.type === 'jwt_bearer') {
      c.listener_auth_type = 'jwt_bearer';
      c.listener_auth_strategy_id = sa.jwt_verification_strategy_id || '';
      any = true;
    } else if (sa.type === 'did_auth') {
      c.listener_auth_type = 'did_auth';
      c.listener_auth_header = sa.extraction?.field || 'Authorization';
      any = true;
    }
  }
  if (t.extension_rules?.required) {
    c.extension_required = true;
    any = true;
  }
  if (t.response_extension_rules?.required) {
    c.response_extension_required = true;
    any = true;
  }
  if (t.custom_metadata?.enabled) {
    c.custom_metadata_enabled = true;
    any = true;
  }
  return any ? c : null;
}

/**
 * Transit Config — surface-wide settings shared by all transit points.
 * Owns the `transit.shared.*` fields (token mode, transit policy, signing,
 * workload binding, response extension rules). Each setting is written to
 * its own dot-notation path so it deep-merges over the transit-point
 * coordinator's defaults.
 */
export const transitConfigDefinition: NodeDefinition = {
  type: 'transit-config',
  label: 'Transit Settings',
  description: 'Shared settings applied to every transit point',
  icon: '\uf013', // fa-cog
  paletteIcon: 'fa-cog',
  color: '#858796',
  shape: 'circle',
  defaultRadius: 22,
  resizable: true,
  resizeRange: { min: 18, max: 36 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.85,
  stage: 'egress',
  cardinality: 'singleton',
  paletteCategory: 'transitPoints',
  paletteOrder: 7,
  dropMode: 'canvas',
  surfaceWide: true,
  provides: [Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: TransitConfigPanel,
  defaultConfig: () => ({
    transit_token_mode: 'embedded',
    sign_requests: true,
  }),
  summary: c => {
    if (!c) return null;
    const bits: string[] = [];
    if (c.transit_token_mode) bits.push(`token: ${c.transit_token_mode}`);
    if (c.sign_requests === false) bits.push('unsigned');
    if (c.transit_policy_definition_id) bits.push('policy');
    return bits.length > 0 ? bits.join(' · ') : null;
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('transit-config');
    if (!node) return undefined;
    const c = node.config ?? {};
    const slices: PayloadSlice[] = [];
    if (typeof c.outbound_listen_address === 'string' && c.outbound_listen_address.trim()) {
      slices.push({
        path: 'transit.outbound_listen_address',
        value: c.outbound_listen_address.trim(),
      });
    }
    if (c.transit_token_mode) {
      slices.push({ path: 'transit.transit_token_mode', value: c.transit_token_mode });
    }
    if (c.sign_requests !== undefined) {
      slices.push({ path: 'transit.sign_requests', value: !!c.sign_requests });
    }
    if (c.transit_policy_definition_id) {
      slices.push({
        path: 'transit.transit_policy',
        value: { policy_definition_id: c.transit_policy_definition_id },
      });
    }
    if (c.opa_policy_definition_id) {
      slices.push({ path: 'transit.opa_policy_definition_id', value: c.opa_policy_definition_id });
    }
    if (c.rate_limit_requests) {
      slices.push({
        path: 'transit.rate_limit',
        value: {
          requests: parseInt(c.rate_limit_requests, 10),
          window_secs: parseInt(c.rate_limit_window_secs, 10) || 60,
        },
      });
    }
    // Listener auth → transit.source_auth (transit ingress credential
    // validation, separate from the AP's caller_authentication).
    const lat = c.listener_auth_type;
    if (lat && lat !== 'none') {
      const sa = (() => {
        switch (lat) {
          case 'api_key':
            if (!c.listener_auth_secret_id) return null;
            return {
              type: 'api_key',
              extraction: {
                source: 'http_header',
                field: c.listener_auth_header || 'X-API-Key',
              },
              secret_id: c.listener_auth_secret_id,
            };
          case 'jwt_bearer':
            if (!c.listener_auth_strategy_id) return null;
            return {
              type: 'jwt_bearer',
              jwt_verification_strategy_id: c.listener_auth_strategy_id,
              audiences: [],
            };
          case 'did_auth':
            return {
              type: 'did_auth',
              extraction: {
                source: 'http_header',
                field: c.listener_auth_header || 'Authorization',
              },
            };
          default:
            return null;
        }
      })();
      if (sa) slices.push({ path: 'transit.source_auth', value: sa });
    }
    if (c.extension_required) {
      slices.push({ path: 'transit.extension_rules', value: { required: true } });
    }
    if (c.response_extension_required) {
      slices.push({ path: 'transit.response_extension_rules', value: { required: true } });
    }
    if (c.custom_metadata_enabled) {
      slices.push({ path: 'transit.custom_metadata', value: { enabled: true } });
    }
    return slices.length > 0 ? slices : undefined;
  },
};
