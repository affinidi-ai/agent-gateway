/**
 * Element ↔ AgentSurface payload audit.
 *
 * Asserts that every element's `payloadPath` and every edge slot's
 * `payloadPathTemplate` resolves to a real persisted field in
 * `src/config/agent_surface.rs` (mirrored in `agentSurfaceSchema.ts`).
 *
 * If you add an element or slot that writes to a brand-new path:
 *   1. Add the field to `src/config/agent_surface.rs`.
 *   2. Mirror the path into `agentSurfaceSchema.ts`.
 *   3. Re-run this test.
 *
 * If you intentionally write to a UI alias (translated by
 * `src/api.ts` before submit), add it to `UI_ONLY_ALIASES`.
 *
 * KNOWN_BROKEN: the snapshot below pins existing offenders so this
 * test prevents *new* drift while remediation is sequenced. To remove
 * an entry from this list either:
 *  - add the field to `agent_surface.rs` (and mirror in
 *    `agentSurfaceSchema.ts`), OR
 *  - delete the offending element/slot, OR
 *  - route it through the `src/api.ts` translation layer and list
 *    the UI path in `UI_ONLY_ALIASES`.
 */

import { registry } from '../index';
import { EDGE_ARCHETYPES, ANY_EDGE_MW } from '../edges/archetypes';
import { isKnownAgentSurfacePath, normalisePath } from '../agentSurfaceSchema';

// Existing offenders the AgentSurface schema does not yet support.
// DO NOT add to this list — it shrinks only. Empty: the palette has
// been pruned of the broken signing / schema / credential-binding
// elements and the response_extension_rules slot.
const KNOWN_BROKEN_ELEMENT_PATHS: ReadonlySet<string> = new Set([]);

const KNOWN_BROKEN_SLOT_PATHS: ReadonlySet<string> = new Set([]);

const KNOWN_BROKEN_BUILDPAYLOAD: ReadonlySet<string> = new Set([]);

describe('payload audit (element + slot paths must resolve to AgentSurface fields)', () => {
  it('recognizes the API-managed MCP metadata output preference', () => {
    expect(isKnownAgentSurfacePath('mcp_legacy_metadata_output')).toBe(true);
  });

  it('recognizes endpoint-local MCP HTTP settings', () => {
    for (const path of ['mcp_http', 'transit.points[*].mcp_http']) {
      expect(isKnownAgentSurfacePath(path)).toBe(true);
    }
    expect(isKnownAgentSurfacePath('access_point.mcp_http')).toBe(false);
  });

  it('does not recognize the removed MCP protocol mode setting', () => {
    for (const path of [
      'mcp_protocol_mode',
      'transit.points[*].mcp_protocol_mode',
      'target.mcp_protocol_mode',
    ]) {
      expect(isKnownAgentSurfacePath(path)).toBe(false);
    }
  });

  it('every element with a payloadPath writes to a known AgentSurface field', () => {
    const offenders: Array<{ type: string; path: string }> = [];
    for (const def of registry.all()) {
      if (!def.payloadPath) continue;
      if (isKnownAgentSurfacePath(def.payloadPath)) continue;
      const key = `${def.type}:${def.payloadPath}`;
      if (KNOWN_BROKEN_ELEMENT_PATHS.has(key)) continue;
      offenders.push({ type: def.type, path: def.payloadPath });
    }
    expect(offenders).toEqual([]);
  });

  it('every typed edge slot template resolves to a known AgentSurface field', () => {
    const offenders: Array<{ archetype: string; slotId: string; path: string }> = [];
    for (const arch of EDGE_ARCHETYPES) {
      for (const slot of arch.slots) {
        if (slot.accepts === ANY_EDGE_MW) continue;
        if (!slot.payloadPathTemplate) continue;
        const normalised = normalisePath(slot.payloadPathTemplate);
        if (isKnownAgentSurfacePath(normalised)) continue;
        const key = `${arch.id}:${slot.id}:${slot.payloadPathTemplate}`;
        if (KNOWN_BROKEN_SLOT_PATHS.has(key)) continue;
        offenders.push({
          archetype: arch.id,
          slotId: slot.id,
          path: slot.payloadPathTemplate,
        });
      }
    }
    expect(offenders).toEqual([]);
  });

  it('every element actually invoked by buildPayload writes to a known field', () => {
    // Drop one of every element type onto a synthetic surface and
    // ask each `buildPayload` what slices it would emit. Catches
    // direct path emissions that bypass the declarative
    // `payloadPath` attribute.
    const ctxBase = {
      protocol: 'a2a' as const,
      surfaceMeta: { name: 'audit', tags: [], status: 'active' as const },
    };
    const offenders: Array<{ type: string; path: string }> = [];
    for (const def of registry.all()) {
      if (!def.buildPayload) continue;
      const probeNode = {
        id: `${def.type}-probe`,
        type: def.type,
        config: def.defaultConfig?.() ?? {},
      };
      const ctx = {
        ...ctxBase,
        allNodes: [probeNode],
        nodesOfType: (t: string) => (t === def.type ? [probeNode] : []),
        firstNodeOfType: (t: string) => (t === def.type ? probeNode : undefined),
      };
      let slices: any;
      try {
        slices = def.buildPayload(ctx as any);
      } catch {
        continue;
      }
      if (!slices) continue;
      for (const s of slices) {
        if (!s?.path) continue;
        if (isKnownAgentSurfacePath(s.path)) continue;
        const key = `${def.type}:${s.path}`;
        if (KNOWN_BROKEN_BUILDPAYLOAD.has(key)) continue;
        offenders.push({ type: def.type, path: s.path });
      }
    }
    expect(offenders).toEqual([]);
  });
});
