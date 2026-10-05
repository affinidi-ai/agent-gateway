import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import type { CanvasNode } from '../../SurfaceCanvas';
import { isTransitPointType } from '../edges/archetypes';
import McpToolGatingPanel from './McpToolGatingPanel';
import McpToolGatingFullscreen from './McpToolGatingFullscreen';
import { DOCS_URL } from '../../../../config/docs';

/**
 * MCP Tool Gating element.
 *
 * A condition-gated allow/deny firewall over the MCP tool surface. Each gate
 * pairs an optional OPA *condition* (a surface policy — ALLOW activates the
 * gate) with an *action* (allow-list or deny-list regex over tool names). The
 * gateway applies the firewall to both the `tools/list` response (hiding
 * tools) and `tools/call` requests (blocking invocation), so a tool hidden
 * from the list cannot be called.
 *
 * Config shape mirrors the backend `McpToolGatingConfig`
 * (see `src/config/agent_surface.rs`):
 *   { gates: [ { id, name, description,
 *               condition_policy_definition_id?,
 *               action: { effect: 'allow' | 'deny', patterns: string[] } } ] }
 *
 * Persisted to `target.mcp_tool_gating`. MCP surfaces only; docks on the
 * response edge from the external target or a transit point.
 */

interface RawGate {
  id?: string;
  name?: string;
  description?: string;
  condition_policy_definition_id?: string | null;
  action?: { effect?: 'allow' | 'deny'; patterns?: unknown };
}

function cleanGates(raw: unknown): RawGate[] {
  return Array.isArray(raw) ? (raw as RawGate[]) : [];
}

function normaliseGate(gate: RawGate): Record<string, unknown> | null {
  const effect = gate.action?.effect === 'allow' ? 'allow' : 'deny';
  const patterns = Array.isArray(gate.action?.patterns)
    ? (gate.action!.patterns as unknown[]).filter(
        (p): p is string => typeof p === 'string' && p.trim() !== ''
      )
    : [];
  if (patterns.length === 0) return null;
  const condition =
    typeof gate.condition_policy_definition_id === 'string' &&
    gate.condition_policy_definition_id.trim() !== ''
      ? gate.condition_policy_definition_id.trim()
      : undefined;
  return {
    id:
      typeof gate.id === 'string' && gate.id
        ? gate.id
        : `gate-${Math.random().toString(36).slice(2, 10)}`,
    ...(gate.name ? { name: gate.name } : {}),
    ...(gate.description ? { description: gate.description } : {}),
    ...(condition ? { condition_policy_definition_id: condition } : {}),
    action: { effect, patterns },
  };
}

function parentIsTransitPoint(node: CanvasNode, allNodes: CanvasNode[]): boolean {
  const parent = node.parentId ? allNodes.find(n => n.id === node.parentId) : undefined;
  return !!parent && isTransitPointType(parent.type);
}

/**
 * Normalise a gating node's config to the wire slice. Emits `default_effect`
 * only when it is `deny` (the backend defaults it to `allow` and omits it),
 * and `gates` only when at least one gate has an effective pattern. Returns
 * `undefined` for a no-op config (allow-by-default with no gates). Shared by
 * this element's surface-wide `buildPayload` and the Transit Point factory
 * (which owns the per-TP `transit.points[i].mcp_tool_gating` slice).
 */
export function mcpToolGatingConfigToWire(
  config: Record<string, unknown> | undefined
): { default_effect?: 'deny'; gates?: Record<string, unknown>[] } | undefined {
  const cleaned = cleanGates(config?.gates)
    .map(normaliseGate)
    .filter((g): g is Record<string, unknown> => g !== null);
  const denyByDefault = config?.default_effect === 'deny';
  // Allow-by-default with no effective gate is a no-op — persist nothing.
  if (cleaned.length === 0 && !denyByDefault) return undefined;
  return {
    ...(denyByDefault ? { default_effect: 'deny' as const } : {}),
    ...(cleaned.length > 0 ? { gates: cleaned } : {}),
  };
}

export const mcpToolGatingDefinition: NodeDefinition = {
  type: 'mcp-tool-gating',
  label: 'MCP Tool Gating',
  description: 'Condition-gated allow/deny filtering of MCP tools (MCP only)',
  icon: '\uf0b0', // fa-filter
  paletteIcon: 'fa-filter',
  color: '#6f42c1',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.7,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 3,
  dropMode: 'edge',
  directionality: 'response',
  edgeSnap: { archetypes: ['ma-external', 'ma-tp'] },
  protocols: ['mcp'],
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.MCP_TOOL_TARGET],
  },
  help: {
    title: 'MCP Tool Gating',
    docLink: DOCS_URL.mcpToolsElement,
    bodyHtml: `
      <p>A condition-gated <strong>allow/deny firewall</strong> over this
      Surface's MCP tools. It applies to both the <code>tools/list</code>
      response (hiding tools) and <code>tools/call</code> requests (blocking
      invocation), so a tool hidden from the list cannot be called.</p>
      <p>Configure one or more <strong>Tool Gates</strong> in the fullscreen
      editor. Each gate has:</p>
      <ul>
        <li><strong>Condition</strong>: an OPA surface policy that decides
        whether the gate is active. An <em>allow</em> result activates it; a
        deny skips it. Choosing <em>“always enforce”</em> makes it
        unconditional.</li>
        <li><strong>Action</strong>: <em>Allow</em> (matching tools form an
        allow-list) or <em>Deny</em> (matching tools are hidden), plus one or
        more regex patterns over tool names.</li>
      </ul>
      <p><strong>Firewall order:</strong> a tool is hidden if any active Deny
      gate matches it; when any active Allow gate exists a tool must match one
      to survive. Deny always overrides Allow.</p>
      <p><strong>Where it docks:</strong> the response edge from the external
      target (the MCP server) or a Transit Point. MCP Surfaces only.</p>
    `,
  },
  incompleteReason: config => {
    const gates = cleanGates(config?.gates);
    if (gates.length === 0) {
      // No gates is valid either way: "allow by default" = allow all,
      // "deny by default" = deny all — the two no-override extremes.
      return null;
    }
    const bad = gates.find(g => {
      const patterns = Array.isArray(g.action?.patterns)
        ? (g.action!.patterns as unknown[]).filter(
            p => typeof p === 'string' && (p as string).trim() !== ''
          )
        : [];
      return patterns.length === 0;
    });
    return bad ? 'Every tool gate needs at least one regex pattern' : null;
  },
  validate: config => {
    const errs: Array<{ field?: string; message: string }> = [];
    const gates = cleanGates(config?.gates);
    gates.forEach((g, idx) => {
      const label = g.name?.trim() || g.id || `Gate ${idx + 1}`;
      const patterns = Array.isArray(g.action?.patterns)
        ? (g.action!.patterns as unknown[]).filter(
            (p): p is string => typeof p === 'string' && p.trim() !== ''
          )
        : [];
      if (patterns.length === 0) {
        errs.push({ message: `Tool gate "${label}" needs at least one regex pattern` });
      }
      for (const p of patterns) {
        try {
          // eslint-disable-next-line no-new
          new RegExp(p);
        } catch {
          errs.push({ message: `Tool gate "${label}" has an invalid regex: ${p}` });
        }
      }
    });
    return errs;
  },
  ConfigPanel: McpToolGatingPanel,
  FullscreenPanel: McpToolGatingFullscreen,
  payloadPath: 'target.mcp_tool_gating',
  defaultConfig: () => ({ default_effect: 'allow', gates: [] }),
  summary: config => {
    const denyByDefault = config?.default_effect === 'deny';
    const n = cleanGates(config?.gates).length;
    if (denyByDefault)
      return n > 0 ? `Deny by default · ${n} gate${n === 1 ? '' : 's'}` : 'Deny all';
    return n > 0 ? `${n} gate${n === 1 ? '' : 's'}` : null;
  },
  buildPayload: ctx => {
    // Surface-wide setting on the external target only. Transit-Point-parented
    // gating nodes are owned by the TP factory (which folds them into
    // `transit.points[i].mcp_tool_gating`), so skip them here. Prefer the
    // first non-TP instance that carries a meaningful config (gates or a
    // deny-by-default baseline), so dropping the circle on both the EXT and a
    // TP response edge still yields one coherent `target.mcp_tool_gating`.
    const nodes = ctx
      .nodesOfType('mcp-tool-gating')
      .filter(n => !parentIsTransitPoint(n, ctx.allNodes as CanvasNode[]));
    const node =
      nodes.find(
        n => cleanGates(n.config?.gates).length > 0 || n.config?.default_effect === 'deny'
      ) ?? nodes[0];
    const slice = mcpToolGatingConfigToWire(node?.config);
    if (!slice) return undefined;
    const slices: PayloadSlice[] = [{ path: 'target.mcp_tool_gating', value: slice }];
    return slices;
  },
  configFromPayload: slice => {
    if (!slice || typeof slice !== 'object') return { default_effect: 'allow', gates: [] };
    const s = slice as { default_effect?: unknown; gates?: unknown };
    return {
      default_effect: s.default_effect === 'deny' ? 'deny' : 'allow',
      gates: cleanGates(s.gates),
    };
  },
};
