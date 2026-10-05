/**
 * Sort + protocol helpers for surface templates. Order is by the
 * optional `sort_priority` field (lower first) with a tie-break on
 * case-insensitive name; unset values sink to the bottom.
 */

import type { SurfaceTemplate } from '../../../api';
import type { Protocol } from '../elements/types';

const DEFAULT_SORT_PRIORITY = Number.MAX_SAFE_INTEGER;

export function templateSortPriority(t: SurfaceTemplate): number {
  return typeof t.sort_priority === 'number' ? t.sort_priority : DEFAULT_SORT_PRIORITY;
}

export function compareTemplatesForDisplay(a: SurfaceTemplate, b: SurfaceTemplate): number {
  const pa = templateSortPriority(a);
  const pb = templateSortPriority(b);
  if (pa !== pb) return pa - pb;
  return (a.name ?? '').toLowerCase().localeCompare((b.name ?? '').toLowerCase());
}

export function sortTemplatesForDisplay(list: readonly SurfaceTemplate[]): SurfaceTemplate[] {
  return [...list].sort(compareTemplatesForDisplay);
}

export interface TemplateProtocolMeta {
  key: string;
  label: string;
  badgeClass: string;
}

const KNOWN_PROTOCOL_BADGES: Record<string, TemplateProtocolMeta> = {
  a2a: { key: 'a2a', label: 'A2A', badgeClass: 'text-bg-primary' },
  ap2: { key: 'ap2', label: 'AP2', badgeClass: 'text-bg-warning' },
  mcp: { key: 'mcp', label: 'MCP', badgeClass: 'text-bg-info' },
  didcomm: { key: 'didcomm', label: 'DIDComm', badgeClass: 'text-bg-success' },
};

/**
 * Best-effort access-point protocol extraction. Returns `null` when
 * the template carries no protocol hint we recognise.
 */
export function getTemplateProtocol(t: SurfaceTemplate): string | null {
  const fromSurface = t.surface?.access_point?.protocol;
  if (typeof fromSurface === 'string' && fromSurface.trim()) {
    return fromSurface.trim().toLowerCase();
  }
  for (const tag of t.tags ?? []) {
    const lower = typeof tag === 'string' ? tag.toLowerCase() : '';
    if (lower in KNOWN_PROTOCOL_BADGES) return lower;
  }
  return null;
}

export function templateMatchesProtocol(t: SurfaceTemplate, protocol: Protocol): boolean {
  const templateProtocol = getTemplateProtocol(t);
  return templateProtocol === null || templateProtocol === protocol;
}

export function getTemplateProtocolBadge(t: SurfaceTemplate): TemplateProtocolMeta | null {
  const key = getTemplateProtocol(t);
  return key ? (KNOWN_PROTOCOL_BADGES[key] ?? null) : null;
}
