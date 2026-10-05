import type { CanvasNode } from '../SurfaceCanvas';
import type { SurfaceNodeType } from '../nodeTypes';
import { registry } from './registry';

/**
 * Stable id prefixes for the synthesised nodes. Synthetic nodes never
 * enter `state.nodes`, so they are not persisted and do not affect
 * `buildPayload`/`buildCanvasBlob`. The prefixes also let downstream
 * code recognise a click target as synthetic.
 */
export const SYNTH_HOP_PREFIX = '__synth_gw_hop__';
export const SYNTH_REMOTE_PREFIX = '__synth_remote_gw__';
export const SYNTH_REMOTE_CHANNEL_PREFIX = '__synth_remote_ch__';

// Parent config fields that back the user-editable names of the
// synthesised nodes. The synth nodes themselves are view-only — the
// name is persisted on the underlying target/TP so it survives
// across renders and reloads.
export const FABRIC_HOP_NAME_FIELD = 'fabric_hop_name';
export const FABRIC_REMOTE_GW_NAME_FIELD = 'fabric_remote_gateway_name';
export const FABRIC_REMOTE_CHANNEL_NAME_FIELD = 'fabric_remote_channel_name';

export function isSyntheticFabricNodeId(id: string | undefined | null): boolean {
  if (!id) return false;
  return (
    id.startsWith(SYNTH_HOP_PREFIX) ||
    id.startsWith(SYNTH_REMOTE_PREFIX) ||
    id.startsWith(SYNTH_REMOTE_CHANNEL_PREFIX)
  );
}

/**
 * Map a synthesised node id back to its underlying parent (the
 * target/TP that owns the `fabric://` endpoint) plus the parent
 * `config` field that stores this synth node's user-editable name.
 * Returns null when the id isn't a recognised synth id.
 */
export function resolveSyntheticNameBinding(
  id: string
): { parentId: string; field: string } | null {
  if (id.startsWith(SYNTH_HOP_PREFIX)) {
    return { parentId: id.substring(SYNTH_HOP_PREFIX.length), field: FABRIC_HOP_NAME_FIELD };
  }
  if (id.startsWith(SYNTH_REMOTE_PREFIX)) {
    return {
      parentId: id.substring(SYNTH_REMOTE_PREFIX.length),
      field: FABRIC_REMOTE_GW_NAME_FIELD,
    };
  }
  if (id.startsWith(SYNTH_REMOTE_CHANNEL_PREFIX)) {
    return {
      parentId: id.substring(SYNTH_REMOTE_CHANNEL_PREFIX.length),
      field: FABRIC_REMOTE_CHANNEL_NAME_FIELD,
    };
  }
  return null;
}

interface FabricRef {
  kind: 'fabric';
  gateway_id: string;
  gateway_channel: string;
}

interface ProxyRef {
  kind: 'proxy';
  mcp_proxy_id: string;
}

type EndpointRef = FabricRef | ProxyRef;

/**
 * Pull `gateway_id`/`gateway_channel` from a node's config. Falls back
 * to parsing the `fabric://` URL when the explicit fields are missing
 * (older surfaces saved before the panel started persisting them).
 * Also recognises the `proxy://{mcp_proxy_id}` form used when the
 * target is a managed MCP proxy fronting a REST API.
 */
function fabricRefForNode(node: CanvasNode): EndpointRef | null {
  const cfg = node.config ?? {};
  const endpoint: string =
    typeof cfg.target_endpoint === 'string'
      ? cfg.target_endpoint
      : typeof cfg.endpoint === 'string'
        ? cfg.endpoint
        : '';
  if (endpoint.startsWith('fabric://')) {
    let gw: string = typeof cfg.gateway_id === 'string' ? cfg.gateway_id : '';
    let ch: string = typeof cfg.gateway_channel === 'string' ? cfg.gateway_channel : '';
    if (!gw || !ch) {
      const path = endpoint.substring('fabric://'.length);
      const parts = path.split('/');
      if (!gw) gw = parts[0] || '';
      if (!ch) ch = parts[1] || '';
    }
    if (!gw || !ch) return null;
    return { kind: 'fabric', gateway_id: gw, gateway_channel: ch };
  }
  if (endpoint.startsWith('proxy://')) {
    const id =
      typeof cfg.mcp_proxy_id === 'string' && cfg.mcp_proxy_id
        ? cfg.mcp_proxy_id
        : endpoint.substring('proxy://'.length).split('/')[0] || '';
    if (!id) return null;
    return { kind: 'proxy', mcp_proxy_id: id };
  }
  return null;
}

/**
 * Returns a node-display list with a synthesised
 * `local-gateway-hop → remote-gateway` chain inserted in place of the
 * existing `npc-endpoint` child for every Transit Point and the
 * surface Target whose endpoint is a `fabric://` URL.
 *
 * The transformation is purely view-side: the original `state.nodes`
 * array is untouched, so persistence (`buildCanvasBlob`) and edit
 * gestures continue to operate on the unchanged data model. A user
 * who toggles the TP/Target's destination back to a direct URL gets
 * the original `npc-endpoint` rendering on the next render — no
 * mutation, no migration.
 *
 * When `surfaceSize` is provided, the synthesised `local-gateway-hop`
 * is snapped onto the surface perimeter (south edge for the target,
 * north edge for transit-points) so it visually sits on the surface
 * boundary — the gateway-to-gateway hop represents the point at
 * which traffic leaves this gateway, so it belongs on the surface
 * edge alongside the AP and target. The `remote-gateway` then sits
 * further outward, off-surface, where the original `npc-endpoint`
 * would have rendered.
 *
 * Transit Points are themselves border-bound (they already sit on the
 * surface perimeter), so snapping a `local-gateway-hop` onto the same
 * edge stacks the two glyphs on top of each other. For a TP fabric
 * route the hop is therefore omitted entirely: the `remote-gateway` is
 * parented directly on the TP and the chain reads TP → remote-gateway
 * → remote-channel. The Target (MA → External) route keeps the hop
 * because the target sits inside the surface and the hop marks the
 * boundary crossing.
 */
export function synthesizeFabricCanvasNodes(
  nodes: CanvasNode[],
  surfaceSize?: { w: number; h: number }
): CanvasNode[] {
  if (!Array.isArray(nodes) || nodes.length === 0) return nodes;

  // Index npc-endpoint nodes by the parent they sit on so we can hide
  // exactly the one that the synthesised chain replaces (and reuse its
  // canvas position so the visuals don't jump).
  const npcByParent = new Map<string, CanvasNode>();
  for (const n of nodes) {
    if (n.type === 'npc-endpoint' && n.parentId) {
      npcByParent.set(n.parentId, n);
    }
  }

  // Find every parent that should expand into the synthetic chain.
  const expansions: Array<{ parent: CanvasNode; ref: EndpointRef }> = [];
  for (const n of nodes) {
    const isTp = registry.isTransitPointType(n.type);
    const isTarget = n.type === 'target';
    if (!isTp && !isTarget) continue;
    const ref = fabricRefForNode(n);
    if (!ref) continue;
    expansions.push({ parent: n, ref });
  }

  if (expansions.length === 0) return nodes;

  // Hide the npc-endpoints that are being replaced, then append the
  // synthesised chain entries.
  const replacedNpcIds = new Set<string>();
  for (const exp of expansions) {
    const npc = npcByParent.get(exp.parent.id);
    if (npc) replacedNpcIds.add(npc.id);
  }

  const out: CanvasNode[] = [];
  for (const n of nodes) {
    if (replacedNpcIds.has(n.id)) continue;
    out.push(n);
  }

  for (const exp of expansions) {
    const npc = npcByParent.get(exp.parent.id);
    const hopId = `${SYNTH_HOP_PREFIX}${exp.parent.id}`;
    const remoteId = `${SYNTH_REMOTE_PREFIX}${exp.parent.id}`;

    // Geometry: anchor the chain to the parent (target/TP) so it
    // stays on the parent's band (target sits on the south surface
    // edge, a TP sits on the north edge). The original npc-endpoint
    // position — when present — tells us where the chain should
    // *end* (typically just past the surface edge, as placed by
    // auto-layout for the outbound npc); the hop sits midway. When
    // no npc position is available (e.g. user just toggled to
    // fabric://), fall back to a default outward hop along the
    // parent's natural outbound axis (east for target, north for TP).
    const parentPos = exp.parent.position;
    const npcPos = npc?.position;
    const isTpParent = exp.parent.type !== 'target';
    // Transit Points are already border-bound, so the local-gateway-hop
    // would overlap them. Collapse the hop for TP routes and connect
    // the TP straight to the remote-gateway.
    const omitHop = isTpParent;
    // Distance the remote gateway sits past the hop, off-surface.
    // Tuned to keep enough room between the GW-hop on the surface
    // border and the external `Remote GW` glyph so the connecting
    // arrow + its label are clearly legible. Must match
    // `SYNTH_REMOTE_BEYOND_HOP` in SurfaceCanvas (the pin helper there
    // is authoritative; this only seeds the first paint).
    const REMOTE_BEYOND_HOP = 165;
    // Distance the remote-channel external actor hangs below the
    // remote gateway. Vertical (south) by request so the chain reads
    // top-to-bottom: hop → remote GW → remote channel. Must match
    // `SYNTH_REMOTE_CHANNEL_DROP` in SurfaceCanvas.
    const REMOTE_CHANNEL_DROP = 160;

    let hopPos: { x: number; y: number } | undefined;
    let remotePos: { x: number; y: number } | undefined;
    if (parentPos) {
      // Force the chain onto the parent's band so the arrows render
      // cleanly even if a stale npc position drifted off-axis.
      const bandY = parentPos.y;
      // Outward direction the chain should travel from the parent.
      // For a Transit Point parent (which sits on the surface edge)
      // prefer the original npc-endpoint axis (auto-layout has
      // already chosen a sensible side). For a managed-agent (Target)
      // parent the target can sit anywhere inside the surface and
      // any middleware that re-parents it shifts the persisted
      // position around — reading its offset as a direction sends
      // the chain to a random side — so always emit due east.
      let dirX = 0;
      let dirY = 0;
      if (!isTpParent) {
        dirX = 1;
        dirY = 0;
      } else if (npcPos) {
        dirX = npcPos.x - parentPos.x;
        dirY = npcPos.y - parentPos.y;
      }
      if (Math.abs(dirX) < 0.5 && Math.abs(dirY) < 0.5) {
        dirX = isTpParent ? 0 : 1;
        dirY = isTpParent ? -1 : 0;
      }
      // Snap the hop onto the surface perimeter along that
      // direction. The hop visualises the boundary at which traffic
      // leaves this gateway — it belongs ON the surface edge
      // alongside the AP and TP. Falls back to a fixed outward
      // offset only when surface dimensions are unavailable or the
      // parent already sits on/past the perimeter.
      if (surfaceSize) {
        const halfW = surfaceSize.w / 2;
        const halfH = surfaceSize.h / 2;
        const tCandidates: number[] = [];
        if (Math.abs(dirX) > 0.001) {
          const targetX = dirX > 0 ? halfW : -halfW;
          const t = (targetX - parentPos.x) / dirX;
          if (t > 0.05) tCandidates.push(t);
        }
        if (Math.abs(dirY) > 0.001) {
          const targetY = dirY > 0 ? halfH : -halfH;
          const t = (targetY - parentPos.y) / dirY;
          if (t > 0.05) tCandidates.push(t);
        }
        if (tCandidates.length > 0) {
          const tEdge = Math.min(...tCandidates);
          hopPos = {
            x: parentPos.x + dirX * tEdge,
            y: parentPos.y + dirY * tEdge,
          };
        }
      }
      if (!hopPos) {
        // Parent already on the perimeter (TP) or no surfaceSize —
        // place the hop a fixed step outward.
        const len = Math.hypot(dirX, dirY) || 1;
        const stepX = (dirX / len) * REMOTE_BEYOND_HOP;
        const stepY = (dirY / len) * REMOTE_BEYOND_HOP;
        hopPos = { x: parentPos.x + stepX, y: parentPos.y + stepY };
      }
      // Remote gateway sits one more step past the hop along the
      // same outward direction, off-surface.
      const len = Math.hypot(dirX, dirY) || 1;
      const rStepX = (dirX / len) * REMOTE_BEYOND_HOP;
      const rStepY = (dirY / len) * REMOTE_BEYOND_HOP;
      remotePos = { x: hopPos.x + rStepX, y: hopPos.y + rStepY };
      // Keep the chain locked to the parent's band so arrows render
      // as straight lines.
      hopPos.y = bandY;
      remotePos.y = bandY;
    }

    // When the hop is collapsed (TP routes) the remote-gateway can't
    // reuse `hopPos` — that snaps onto the surface perimeter, which a
    // Transit Point already sits on, so the remote-gateway would land
    // on top of the TP. Instead place it a fixed step radially outward
    // from the surface centre through the TP (parentPos is the offset
    // from centre, so the centre is the origin), and continue the
    // remote-channel one more step along the same axis. This mirrors
    // the pinning loop in SurfaceCanvas exactly, so the position hint
    // the `externalRevision` re-sync pushes into fx/fy after an
    // auto-layout agrees with the per-render pin and the chain reads
    // as a straight line pointing off-surface. Target routes keep the
    // hop and place the remote one step beyond it.
    let remoteNodePos = remotePos;
    let collapsedChannelPos: { x: number; y: number } | undefined;
    if (omitHop && parentPos) {
      let ox = parentPos.x;
      let oy = parentPos.y;
      if (Math.abs(ox) < 0.5 && Math.abs(oy) < 0.5) {
        ox = 0;
        oy = -1;
      }
      const olen = Math.hypot(ox, oy) || 1;
      const ux = ox / olen;
      const uy = oy / olen;
      remoteNodePos = {
        x: parentPos.x + ux * REMOTE_BEYOND_HOP,
        y: parentPos.y + uy * REMOTE_BEYOND_HOP,
      };
      collapsedChannelPos = {
        x: parentPos.x + ux * (REMOTE_BEYOND_HOP + REMOTE_CHANNEL_DROP),
        y: parentPos.y + uy * (REMOTE_BEYOND_HOP + REMOTE_CHANNEL_DROP),
      };
    }

    // Names persisted on the parent — surface them as the synth
    // node's `config.name` so the default Name field in the
    // properties panel reads and writes them transparently. The
    // routing of the write back to the parent's config happens in
    // the click/update layer (see `resolveSyntheticNameBinding`).
    const parentCfg = exp.parent.config ?? {};
    const hopName =
      typeof parentCfg[FABRIC_HOP_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_HOP_NAME_FIELD] as string)
        : '';
    const remoteGwName =
      typeof parentCfg[FABRIC_REMOTE_GW_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_REMOTE_GW_NAME_FIELD] as string)
        : '';
    const remoteChName =
      typeof parentCfg[FABRIC_REMOTE_CHANNEL_NAME_FIELD] === 'string'
        ? (parentCfg[FABRIC_REMOTE_CHANNEL_NAME_FIELD] as string)
        : '';

    const isProxy = exp.ref.kind === 'proxy';

    const hop: CanvasNode = {
      id: hopId,
      type: 'local-gateway-hop' as SurfaceNodeType,
      label: hopName || (isProxy ? 'MCP Proxy' : 'GW'),
      configured: true,
      parentId: exp.parent.id,
      // `kind` lets the shared hop sidebar branch its helper text
      // between the fabric:// (Remote Gateway) and proxy:// (MCP
      // Proxy) flavours without having to walk back to the parent.
      config: {
        name: hopName,
        kind: isProxy ? 'proxy' : 'fabric',
        ...(isProxy && parentCfg.mcp_tool_policies !== undefined
          ? { mcp_tool_policies: parentCfg.mcp_tool_policies }
          : {}),
      },
      ...(hopPos ? { position: hopPos } : {}),
      connectionDirection: 'outbound',
    };

    const remoteConfig: Record<string, any> = isProxy
      ? {
          name: remoteGwName,
          // `kind` lets the shared panel branch between fabric-gateway
          // and mcp-proxy renderings; both routes share the same
          // synthesised types so the canvas geometry stays identical.
          kind: 'proxy',
          mcp_proxy_id: (exp.ref as ProxyRef).mcp_proxy_id,
        }
      : {
          name: remoteGwName,
          kind: 'fabric',
          gateway_id: (exp.ref as FabricRef).gateway_id,
          gateway_channel: (exp.ref as FabricRef).gateway_channel,
        };

    const remote: CanvasNode = {
      id: remoteId,
      type: 'remote-gateway' as SurfaceNodeType,
      label: remoteGwName || (isProxy ? 'REST API' : 'Remote GW'),
      configured: true,
      parentId: omitHop ? exp.parent.id : hopId,
      config: remoteConfig,
      ...(remoteNodePos ? { position: remoteNodePos } : {}),
      connectionDirection: 'outbound',
      description: isProxy ? 'REST API fronted by the MCP proxy' : 'Remote GW + Agent Surface',
    };

    // Remote-channel external actor hangs vertically south of the
    // remote GW. It represents the channel endpoint on the remote
    // gateway that this fabric:// route lands on (or the tools
    // surfaced by the MCP proxy for the proxy:// flavour).
    const remoteChannelId = `${SYNTH_REMOTE_CHANNEL_PREFIX}${exp.parent.id}`;
    const remoteChannelPos = collapsedChannelPos
      ? collapsedChannelPos
      : remoteNodePos
        ? { x: remoteNodePos.x, y: remoteNodePos.y + REMOTE_CHANNEL_DROP }
        : undefined;
    const remoteChannelConfig: Record<string, any> = isProxy
      ? {
          name: remoteChName,
          kind: 'proxy',
          mcp_proxy_id: (exp.ref as ProxyRef).mcp_proxy_id,
        }
      : {
          name: remoteChName,
          kind: 'fabric',
          gateway_id: (exp.ref as FabricRef).gateway_id,
          gateway_channel: (exp.ref as FabricRef).gateway_channel,
        };
    const remoteChannel: CanvasNode = {
      id: remoteChannelId,
      type: 'remote-channel' as SurfaceNodeType,
      label: remoteChName || (isProxy ? 'MCP Tools' : 'Remote Surface'),
      configured: true,
      parentId: remoteId,
      config: remoteChannelConfig,
      ...(remoteChannelPos ? { position: remoteChannelPos } : {}),
      connectionDirection: 'outbound',
      description: isProxy
        ? 'MCP tools exposed by the proxy'
        : 'Agent Surfaces on the remote gateway',
    };

    if (omitHop) {
      out.push(remote, remoteChannel);
    } else {
      out.push(hop, remote, remoteChannel);
    }
  }

  return out;
}
