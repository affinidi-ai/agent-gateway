/**
 * Pure auto-layout algorithm for the surface builder.
 *
 * Layout rules:
 *   • AP is always on the WEST edge of the surface.
 *   • MA sits at the centre of the interior bounding box.
 *   • Each TP is assigned to one of N / S / E edges based on the
 *     angle from the surface centre to its CURRENT position. (West
 *     is reserved for the AP; anything pointing west snaps to the
 *     nearest of N / S.) When a TP is dropped on a diagonal the
 *     angle-quadrant logic picks the closest cardinal edge — i.e.
 *     the edge that yields the cleanest 90° pipe from MA, with the
 *     residual rendered as the natural 30°-ish offset by the canvas.
 *   • TPs on the same edge are evenly spread along that edge,
 *     preserving their relative order (so peers keep their
 *     horizontal / vertical ranking).
 *   • Each TP's NPC hops further outward perpendicular to its edge
 *     (N→further north, etc.), short hop.
 *   • Outbound MA-NPCs hop EAST, aligned with MA's y.
 *   • Middleware sit at evenly distributed t along their pipe with
 *     a canonical lateral offset.
 *   • Every pair of connected anchors enforces a MIN_EDGE_LEN of
 *     edge-to-edge arrow length so no link collapses to a stub.
 *   • Surface width and height are grown to fit the interior with
 *     padding; the layout result is recentred so the geometric mean
 *     of the interior sits on the surface centre.
 */

import type { CanvasNode } from './SurfaceCanvas';
import { registry } from './elements';
import { deriveEdges } from './elements/edges/deriveEdges';
import { getArchetype } from './elements/edges/archetypes';
import type { SlotDirection } from './elements/edges/types';

export interface AutoLayoutResult {
  surfaceSize: { w: number; h: number };
  positions: Array<{ id: string; x: number; y: number }>;
}

const MIN_W = 460;
const MIN_H = 200;
const PAD = 30; // padding between surface edge and interior content
const NPC_HOP = 70; // edge-to-edge gap between surface and external NPC
const MIN_EDGE_LEN = 70; // min edge-to-edge arrow length between connected anchors
const MW_SLOT_W = 60; // horizontal budget per middleware slot along a pipe
const LATERAL = 28; // perpendicular offset of middleware glyph from pipe
const PEER_GAP = 90; // min centre-to-centre between two peers on the same edge
// Canvas-side render offsets that shorten the visible TP↔NPC arrow.
// Must match SurfaceCanvas.tsx labelOffset coefficients. North-side
// TP→NPC arrows have to add these to the geometric hop so the visible
// arrow body stays comparable to east/west links (which incur neither
// offset because uyp ≈ 0).
const CANVAS_TGT_LABEL_OFFSET = 39; // peak: -uyp * 39 for tgt label clearance
const CANVAS_SRC_BIDI_OFFSET = 20; // bidirectional src side label clearance
// Extra horizontal clearance for east-going MA→outbound-NPC links so the
// arrow tip doesn't land on top of the NPC name label (which renders
// centred below the NPC and extends left of the NPC's circle).
const EAST_NPC_LABEL_CLEARANCE = 40;
// Extra MA→TP pipe length beyond the geometric minimum, so the visible
// arrow body has breathing room.
const MA_TP_EXTRA = 20;
const GRID = 10;
const snap = (v: number) => Math.round(v / GRID) * GRID;
const SURFACE_PAD = 30;

function radiusOf(n: CanvasNode, fallback = 24): number {
  return n.radius ?? fallback;
}

export function computeAutoLayout(nodes: CanvasNode[]): AutoLayoutResult {
  const byId = new Map(nodes.map(n => [n.id, n] as const));
  const ap = nodes.find(n => n.type === 'access-point');
  const target = nodes.find(n => n.type === 'target');
  const tps = nodes.filter(n => registry.isTransitPointType(n.type));
  const human = nodes.find(n => n.type === 'human');
  const caller = nodes.find(n => n.type === 'caller');
  const npcs = nodes.filter(n => n.type === 'npc-endpoint' && n.parentId);
  const edges = deriveEdges(nodes);

  const apR = ap ? radiusOf(ap, 36) : 36;
  const maR = target ? radiusOf(target, 28) : 28;

  // ── Sort TPs left-to-right by current x (deterministic) ────────
  const sortedTps = [...tps].sort(
    (a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id)
  );
  const N = sortedTps.length;
  const maxTpR = N === 0 ? 36 : Math.max(...sortedTps.map(t => radiusOf(t, 36)));
  const peerGap = Math.max(PEER_GAP, 2 * maxTpR + 55);
  const tpSpan = N === 0 ? 0 : Math.max(0, N - 1) * peerGap;

  // ── NPC index ──────────────────────────────────────────────────
  const npcsByAnchor = new Map<string, CanvasNode[]>();
  for (const n of npcs) {
    if (!n.parentId) continue;
    const list = npcsByAnchor.get(n.parentId) ?? [];
    list.push(n);
    npcsByAnchor.set(n.parentId, list);
  }

  // ── Middleware counts per archetype ────────────────────────────
  const apMaEdge = edges.find(e => e.archetype === 'ap-ma');
  let mwOnApMa = 0;
  if (apMaEdge) {
    for (const occList of apMaEdge.slots.values()) mwOnApMa += occList.length;
  }
  let mwOnMaExternalMax = 0;
  let mwOnMaTpMax = 0;
  for (const e of edges) {
    let n = 0;
    for (const occList of e.slots.values()) n += occList.length;
    if (e.archetype === 'ma-external') mwOnMaExternalMax = Math.max(mwOnMaExternalMax, n);
    else if (e.archetype === 'ma-tp') mwOnMaTpMax = Math.max(mwOnMaTpMax, n);
  }

  // ── Zones around MA (placed at surface centre x=0, y=0) ────────
  // West: AP — middleware — MA. AP sits this far west of MA.
  const westZone = apR + MIN_EDGE_LEN + mwOnApMa * MW_SLOT_W + maR;
  // East: MA — middleware — (outbound NPC if any). Used to size halfW
  // so the outbound NPC sits cleanly past the surface edge.
  const outboundNpcR = (() => {
    if (!target) return 18;
    const list = npcsByAnchor.get(target.id) ?? [];
    return list.length > 0 ? radiusOf(list[0], 18) : 18;
  })();
  const maNpcStack = target ? (npcsByAnchor.get(target.id)?.length ?? 0) : 0;
  // East zone (centre-of-MA → outbound-NPC-centre, when an outbound
  // NPC exists). The NPC then sits NPC_HOP past the surface right edge.
  const eastZone =
    maNpcStack > 0 ? maR + MIN_EDGE_LEN + mwOnMaExternalMax * MW_SLOT_W + outboundNpcR : 0;

  // MA→TP vertical pipe length (centre-to-centre). Scales with the
  // middleware count on any MA→TP pipe so glyphs don't crowd the
  // pipe endpoints. MA_TP_EXTRA gives the visible arrow body extra
  // breathing room beyond the geometric minimum.
  const maTpDist =
    maR + Math.max(MIN_EDGE_LEN, MIN_EDGE_LEN + mwOnMaTpMax * MW_SLOT_W) + maxTpR + MA_TP_EXTRA;

  // ── Surface dimensions ─────────────────────────────────────────
  // AP and TPs are edge-constrained, meaning the runtime
  // `constrainToSurfaceEdge` will snap them to the nearest surface
  // perimeter edge. So halfW must equal the desired AP→MA distance
  // (so AP at -halfW sits at the intended westZone from MA) and
  // halfH must equal the desired MA→TP distance (so TPs at -halfH
  // sit at the intended distance from MA).
  let halfW = Math.max(MIN_W / 2, westZone, eastZone, tpSpan / 2 + maxTpR + SURFACE_PAD);
  // NPC stack (outbound, when >1) extends MA's y range — keep room.
  const stackExtent = maNpcStack > 1 ? maR + (maNpcStack - 1) * 50 + SURFACE_PAD : 0;
  // Surface-bound free-floating nodes (e.g. Trust Registry) get laid
  // out in a row along the south interior band; reserve vertical room
  // so they sit inside the surface rectangle rather than colliding
  // with the MA / pipeline above them.
  const containedFree = nodes.filter(
    n => n.type !== 'target' && registry.get(n.type)?.containedInSurface
  );
  const containedR =
    containedFree.length === 0 ? 0 : Math.max(...containedFree.map(n => radiusOf(n, 22)));
  const containedRowExtent =
    containedFree.length > 0 ? maR + MIN_EDGE_LEN + containedR + SURFACE_PAD : 0;
  let halfH = Math.max(
    MIN_H / 2,
    N > 0 ? maTpDist : maR + SURFACE_PAD,
    maR + SURFACE_PAD,
    stackExtent,
    containedRowExtent
  );

  const positions: Array<{ id: string; x: number; y: number }> = [];

  // ── Anchor positions ───────────────────────────────────────────
  // MA at surface centre. AP on the west perimeter at -halfW.
  const maX = 0;
  const maY = 0;
  if (target) positions.push({ id: target.id, x: maX, y: maY });
  if (ap) positions.push({ id: ap.id, x: -halfW, y: maY });
  if (caller) positions.push({ id: caller.id, x: -halfW - 90, y: maY });
  if (human) positions.push({ id: human.id, x: -halfW - 170, y: maY });

  // ── Place TPs on the north perimeter, evenly centred on MA's x ─
  const tpRowY = -halfH;
  if (N === 1) {
    positions.push({ id: sortedTps[0].id, x: maX, y: tpRowY });
  } else if (N >= 2) {
    const startX = maX - tpSpan / 2;
    for (let i = 0; i < N; i++) {
      positions.push({ id: sortedTps[i].id, x: startX + i * peerGap, y: tpRowY });
    }
  }

  // ── Place TP NPCs ──────────────────────────────────────────────
  // All TP NPCs sit on a single horizontal line above the TP row.
  // Vertical hop includes the canvas-side tgt-label offset and the
  // bidi src offset so the visible arrow body matches east/west links.
  const verticalNpcHop = NPC_HOP + CANVAS_TGT_LABEL_OFFSET + CANVAS_SRC_BIDI_OFFSET;
  const sampleTpNpc = npcs.find(n => {
    const parent = byId.get(n.parentId ?? '');
    return !!parent && registry.isTransitPointType(parent.type);
  });
  const tpNpcR = radiusOf(sampleTpNpc ?? ({ radius: 18 } as CanvasNode), 18);
  const npcRowY = tpRowY - maxTpR - verticalNpcHop - tpNpcR;

  for (let i = 0; i < N; i++) {
    const tp = sortedTps[i];
    const npcList = npcsByAnchor.get(tp.id) ?? [];
    if (npcList.length === 0) continue;
    const tpPos = positions.find(p => p.id === tp.id);
    if (!tpPos) continue;
    // Leftmost / rightmost TP (with ≥3 TPs) gets its NPC pushed past
    // the surface left/right edge, so the arrow runs diagonally and
    // the NPC label sits clear of any neighbouring NPC labels.
    const isLeftCorner = N >= 3 && i === 0;
    const isRightCorner = N >= 3 && i === N - 1;
    let baseX: number;
    if (isLeftCorner) baseX = -halfW - NPC_HOP;
    else if (isRightCorner) baseX = halfW + NPC_HOP;
    else baseX = tpPos.x;
    const baseY = npcRowY;
    for (let j = 0; j < npcList.length; j++) {
      const offsetX = (j - (npcList.length - 1) / 2) * 50;
      positions.push({ id: npcList[j].id, x: baseX + offsetX, y: baseY });
    }
  }

  // ── Outbound MA NPC: hop east past the surface edge ────────────
  if (target) {
    const outboundList = npcsByAnchor.get(target.id) ?? [];
    if (outboundList.length > 0) {
      const r = radiusOf(outboundList[0], 18);
      // Add EAST_NPC_LABEL_CLEARANCE so the arrow tip lands well
      // clear of the NPC's name label (centred below the NPC and
      // typically extending past its left edge).
      const baseX = halfW + NPC_HOP + EAST_NPC_LABEL_CLEARANCE + r;
      for (let i = 0; i < outboundList.length; i++) {
        const offsetY = (i - (outboundList.length - 1) / 2) * 50;
        positions.push({ id: outboundList[i].id, x: baseX, y: maY + offsetY });
      }
    }
  }

  // ── Surface-bound free-floating nodes (e.g. Trust Registry) ────
  // Lay them out in a single row along the south interior band,
  // left-to-right, evenly spread across the surface width. Anchored
  // INSIDE the surface (y = halfH - r - PAD) so the surface-resize
  // clamp never has to push them around after the fact.
  if (containedFree.length > 0) {
    // Stable order so the same set always lands in the same slots.
    const sorted = [...containedFree].sort(
      (a, b) => (a.position?.x ?? 0) - (b.position?.x ?? 0) || a.id.localeCompare(b.id)
    );
    const rowY = halfH - containedR - SURFACE_PAD;
    const innerW = halfW * 2 - 2 * (containedR + SURFACE_PAD);
    const step = sorted.length > 1 ? innerW / (sorted.length - 1) : 0;
    const startX = -halfW + containedR + SURFACE_PAD;
    for (let i = 0; i < sorted.length; i++) {
      const x = sorted.length === 1 ? 0 : startX + i * step;
      positions.push({ id: sorted[i].id, x, y: rowY });
    }
  }

  // ── Middleware: evenly spaced along their pipe ─────────────────
  const newPosOf = (id: string): { x: number; y: number } | undefined => {
    const written = positions.find(p => p.id === id);
    if (written) return { x: written.x, y: written.y };
    const cn = byId.get(id);
    return cn?.position;
  };
  for (const edge of edges) {
    const arch = getArchetype(edge.archetype);
    if (!arch) continue;
    for (const dir of arch.directions as readonly SlotDirection[]) {
      const slots = arch.slots.filter(s => s.direction === dir).sort((a, b) => a.order - b.order);
      const occupants: string[] = [];
      for (const s of slots) {
        const list = edge.slots.get(s.id) ?? [];
        for (const id of list) occupants.push(id);
      }
      if (occupants.length === 0) continue;
      const srcId = dir === 'request' ? edge.endpoints.source : edge.endpoints.target;
      const tgtId = dir === 'request' ? edge.endpoints.target : edge.endpoints.source;
      const sp = newPosOf(srcId);
      const tgtP = newPosOf(tgtId);
      if (!sp || !tgtP) continue;
      const ldx = tgtP.x - sp.x;
      const ldy = tgtP.y - sp.y;
      const llen = Math.sqrt(ldx * ldx + ldy * ldy) || 1;
      const ux = ldx / llen;
      const uy = ldy / llen;
      const nx = -uy;
      const ny = ux;
      const occCount = occupants.length;
      for (let i = 0; i < occCount; i++) {
        const t = (i + 1) / (occCount + 1);
        const bx = sp.x + ux * llen * t;
        const by = sp.y + uy * llen * t;
        const x = bx + nx * LATERAL;
        const y = by + ny * LATERAL;
        positions.push({ id: occupants[i], x, y });
      }
    }
  }

  return {
    surfaceSize: { w: snap(halfW * 2), h: snap(halfH * 2) },
    positions: positions.map(p => ({ id: p.id, x: snap(p.x), y: snap(p.y) })),
  };
}
