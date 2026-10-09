import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import { urlError } from '../validators';
import ManagedAgentPanel from './ManagedAgentPanel';
import ManagedAgentAuthFullscreen from './ManagedAgentAuthFullscreen';
import { DOCS_URL } from '../../../../config/docs';
import { a2aProxyIdFromEndpoint, isA2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';

export const managedAgentDefinition: NodeDefinition = {
  type: 'target',
  label: 'Managed Agent',
  description: 'Upstream endpoint to forward requests to',
  icon: '\uf544', // fa-robot
  paletteIcon: 'fa-robot',
  color: '#17a2b8',
  shape: 'rect',
  defaultRadius: 28, // half of TARGET_SQUARE_SIZE = 56
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: true,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'target',
  cardinality: 'singleton',
  paletteCategory: 'transitPoints',
  paletteOrder: 2,
  dropMode: 'canvas',
  hiddenFromPalette: true, // auto-created with the surface
  deletable: false, // surface always has exactly one managed agent
  provides: [
    Cap.PIPELINE_SINK,
    Cap.SURFACE_INTERIOR,
    Cap.MIDDLEWARE_SLOT,
    Cap.POLICY_TARGET,
    Cap.PAYMENT_TARGET,
    Cap.NETWORKING_TARGET,
    Cap.TRUST_REGISTRY_TARGET,
    Cap.EXTENSION_TARGET,
    Cap.METADATA_TARGET,
    Cap.MCP_TOOL_TARGET,
    Cap.CREDENTIAL_TARGET,
    Cap.IDENTITY_TARGET,
    Cap.WORKLOAD_BINDING_TARGET,
    Cap.NPC_CONNECTABLE,
    Cap.CONFIGURABLE,
    Cap.ATTACHES_TO_TARGET,
  ],
  requires: {
    dropOnNode: [Cap.SURFACE_INTERIOR],
  },
  incompleteReason: config => {
    const type = config.endpoint_type || 'url';
    if (type === 'gateway') {
      if (!config.gateway_id || !config.gateway_channel) return 'Gateway connection is required';
      return null;
    }
    if (type === 'mcp-proxy') {
      if (!config.mcp_proxy_id) return 'MCP Proxy selection is required';
      return null;
    }
    return !config.endpoint ? 'Agent endpoint URL is required' : null;
  },
  validate: c => {
    const errs: Array<{ field?: string; message: string }> = [];
    const type = c.endpoint_type || 'url';
    if (type === 'url') {
      const e = urlError('endpoint', c.endpoint, 'Agent endpoint');
      if (e) errs.push(e);
    } else if (type === 'gateway') {
      if (!c.gateway_id)
        errs.push({ field: 'gateway_id', message: 'Gateway selection is required' });
      if (!c.gateway_channel)
        errs.push({ field: 'gateway_channel', message: 'Agent surface selection is required' });
    } else if (type === 'mcp-proxy') {
      if (!c.mcp_proxy_id)
        errs.push({ field: 'mcp_proxy_id', message: 'MCP Proxy selection is required' });
    }
    return errs;
  },
  defaultConfig: () => ({
    endpoint: 'https://httpbin.org/anything',
    inject_vp: true,
  }),
  help: {
    title: 'Managed Agent',
    docLink: DOCS_URL.managedAgentElement,
    bodyHtml: `
      <p>The Managed Agent is the real agent this surface forwards requests
      to, reached at the Target endpoint (the actual destination behind the
      front door). Every surface needs exactly one.</p>
      <p>Point it at a direct URL, another connected gateway, an MCP Proxy,
      or an A2A Proxy, then optionally configure how the gateway
      authenticates itself to that destination and whether it attaches a
      signed identity credential to outbound calls.</p>
    `,
  },
  ConfigPanel: ManagedAgentPanel,
  FullscreenPanel: ManagedAgentAuthFullscreen,
  summary: c => (c?.endpoint ? c.endpoint : null),
  getListViewInfo: c => {
    const ep: string = typeof c?.endpoint === 'string' ? c.endpoint : '';
    let kind = 'Direct URL';
    if (ep.startsWith('fabric://')) kind = 'Gateway';
    else if (ep.startsWith('proxy://')) kind = 'MCP Proxy';
    else if (isA2aProxyEndpoint(ep)) kind = 'A2A Proxy';
    return {
      extras: [ep || '—', kind, c?.target_auth_enabled ? c.target_auth_type || 'enabled' : 'none'],
    };
  },
  payloadPath: 'target',
  /**
   * The panel uses derived UI fields (`endpoint_type`, `gateway_id`,
   * `gateway_channel`, `mcp_proxy_id`) that are not part of the wire
   * shape — only `endpoint` is persisted. Reverse-derive them from the
   * URL scheme on load so a saved gateway-to-gateway target restores
   * as "via Gateway Connection" instead of falling back to "Direct URL".
   */
  configFromPayload: (slice, _payload) => {
    const c: any = { ...slice };
    // `trust_check_list` is owned by the separate `trust-check` canvas
    // node — strip it here so a legacy target-slice carrying the field
    // never seeds it onto the target panel's state.
    delete c.trust_check_list;
    const ep: string = typeof slice?.endpoint === 'string' ? slice.endpoint : '';
    if (ep.startsWith('fabric://')) {
      c.endpoint_type = 'gateway';
      const rest = ep.slice('fabric://'.length);
      const slash = rest.indexOf('/');
      if (slash > 0) {
        c.gateway_id = rest.slice(0, slash);
        c.gateway_channel = rest.slice(slash + 1);
      }
      if (typeof slice?.fabric_target_name === 'string') {
        c.fabric_target_name = slice.fabric_target_name;
      }
    } else if (ep.startsWith('proxy://')) {
      c.endpoint_type = 'mcp-proxy';
      c.mcp_proxy_id = ep.slice('proxy://'.length);
      // Restore mcp_tool_policies from the backend array → canvas {tools:[...], default_policy_id} shape.
      // The "*" wildcard entry represents the default policy.
      if (Array.isArray(slice?.mcp_tool_policies)) {
        const wildcardEntry = (slice.mcp_tool_policies as any[]).find(
          (e: any) => e.tool_name === '*'
        );
        const perToolEntries = (slice.mcp_tool_policies as any[]).filter(
          (e: any) => e.tool_name !== '*'
        );
        c.mcp_tool_policies = {
          tools: perToolEntries,
          default_policy_id: wildcardEntry?.policy_definition_id || '',
        };
        delete c.mcp_tool_policies_enabled;
      }
    } else if (isA2aProxyEndpoint(ep)) {
      c.endpoint_type = 'a2a-proxy';
      c.a2a_proxy_id =
        typeof slice?.a2a_proxy_id === 'string' ? slice.a2a_proxy_id : a2aProxyIdFromEndpoint(ep);
    } else {
      c.endpoint_type = 'url';
    }
    if (slice?.identity_injection && typeof slice.identity_injection === 'object') {
      c.inject_vp = (slice.identity_injection as { inject_vp?: boolean }).inject_vp !== false;
    } else {
      c.inject_vp = true;
    }
    if (slice?.auth) {
      const ta = slice.auth;
      c.target_auth_enabled = true;
      c.target_auth_fallback = ta.fallback || 'reject';
      const m = ta.method;
      // Wire shape uses an externally-tagged enum: { static_secret: { ... } }.
      // Older saved configs may use the flattened shape with `method: 'static_secret'`
      // and sibling fields, so handle both.
      const ss =
        (typeof m === 'object' ? m?.static_secret : null) || (m === 'static_secret' ? ta : null);
      if (ss) {
        c.target_auth_secret_id = ss.secret_id || '';
        c.target_auth_header_name = ss.header_name || 'Authorization';
        c.target_auth_header_format = ss.header_format || '{value}';

        if (typeof ta.auth_type === 'string') {
          c.target_auth_type = ta.auth_type;
        } else {
          const fmt: string = c.target_auth_header_format;
          if (fmt.startsWith('Bearer ')) c.target_auth_type = 'bearer';
          else if (fmt.startsWith('Basic ')) c.target_auth_type = 'basic';
          else if (c.target_auth_header_name === 'X-API-Key') c.target_auth_type = 'api_key';
          else c.target_auth_type = 'custom';
        }
      }
      delete c.auth;
    }
    return c;
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('target');
    const c = node?.config ?? {};
    const tgt: any = { endpoint: c.endpoint || '' };
    if (isA2aProxyEndpoint(c.endpoint)) {
      tgt.a2a_proxy_id = c.a2a_proxy_id || a2aProxyIdFromEndpoint(c.endpoint);
    }
    if (c.target_auth_enabled && c.target_auth_secret_id) {
      tgt.auth = {
        method: {
          static_secret: {
            secret_id: c.target_auth_secret_id,
            header_name: c.target_auth_header_name || 'Authorization',
            header_format: c.target_auth_header_format || '{value}',
          },
        },
        auth_type: c.target_auth_type || 'bearer',
        fallback: c.target_auth_fallback || 'reject',
      };
    }
    if (
      typeof c.endpoint === 'string' &&
      c.endpoint.startsWith('fabric://') &&
      c.fabric_target_name
    ) {
      tgt.fabric_target_name = c.fabric_target_name;
    }
    if (c.mpp_auto_pay) {
      tgt.mpp_auto_pay = true;
      if (c.mpp_auto_pay_max_amount) tgt.mpp_auto_pay_max_amount = c.mpp_auto_pay_max_amount;
    }
    if (node) {
      tgt.identity_injection = { inject_vp: c.inject_vp !== false };
    }

    // MCP tool policies — set when the user configures them on the MCP Proxy
    // canvas node (tunnelled here from the synthesised hop via handleSynthAwareNodeUpdate).
    // The backend expects target.mcp_tool_policies as an array of tool entries.
    // A default_policy_id is persisted as a wildcard "*" entry at the start of the array.
    if (c.mcp_tool_policies?.tools?.length > 0 || c.mcp_tool_policies?.default_policy_id) {
      const tools: any[] = [];
      if (c.mcp_tool_policies.default_policy_id) {
        tools.push({
          tool_name: '*',
          policy_definition_id: c.mcp_tool_policies.default_policy_id,
          description: 'Default policy',
        });
      }
      tools.push(...(c.mcp_tool_policies.tools || []));
      tgt.mcp_tool_policies = tools;
      tgt.mcp_tool_policies_enabled = true;
    } else {
      tgt.mcp_tool_policies_enabled = false;
    }

    const slices: Array<{ path: string; value: any }> = [{ path: 'target', value: tgt }];
    return slices;
  },
};
