import React from 'react';
import type { CanvasNode } from './SurfaceCanvas';
import { getIncompleteReason } from './SurfaceCanvas';
import { registry } from './elements';
import type { ListViewInfo } from './elements/types';
import { useOptionalSurfaceMeta } from './SurfaceMetaContext';
import { getProtocolLabel } from './protocols';

interface ElementsListTabProps {
  nodes: CanvasNode[];
  surfacePolicyIds: Set<string> | null;
  onSelectNode?: (nodeId: string) => void;
}

interface RowInfo {
  id: string;
  icon?: string;
  color?: string;
  typeLabel: string;
  name: string;
  description: string;
  configured: boolean;
  faultReason: string | null;
  extras: React.ReactNode[];
}

/**
 * Resolve list-view metadata for a node: defer to the element's
 * `getListViewInfo` when present, otherwise synthesise sensible defaults
 * from the canvas label, the static description, and `summary()`.
 */
function resolveRow(node: CanvasNode, surfacePolicyIds: Set<string> | null): RowInfo | null {
  const def = registry.get(node.type);
  if (!def) return null;
  const info: ListViewInfo = def.getListViewInfo ? def.getListViewInfo(node.config ?? {}) : {};
  const summary = !info.extras && def.summary ? def.summary(node.config ?? {}) : null;
  const extras = info.extras ?? (summary ? [summary] : []);
  // Use the same fault reason the Save guard checks (incomplete fields
  // OR validation errors) so the Status badge in this list never
  // disagrees with the toast that blocks Save.
  const faultReason = getIncompleteReason(node.type, node.config ?? {}, surfacePolicyIds);
  return {
    id: node.id,
    icon: def.paletteIcon,
    color: def.color,
    typeLabel: def.label,
    name: info.name ?? node.label ?? def.label,
    description: info.description ?? def.description ?? '',
    configured: faultReason === null,
    faultReason,
    extras,
  };
}

const ElementsListTab: React.FC<ElementsListTabProps> = ({
  nodes,
  surfacePolicyIds,
  onSelectNode,
}) => {
  const meta = useOptionalSurfaceMeta();

  // Synthesise a row for the Surface itself so users can see at a
  // glance whether name/protocol are set. The Surface isn't a real
  // entry in `nodes`, so its validation lives in `computeBlockingReason`
  // on the page; mirror that logic here.
  const surfaceRow: RowInfo | null = (() => {
    const def = registry.get('surface');
    if (!def) return null;
    const missing: string[] = [];
    if (!meta?.name?.trim()) missing.push('name');
    if (!meta?.protocol) missing.push('protocol');
    const faultReason = missing.length > 0 ? `${missing.join(' and ')} required` : null;
    const extras: React.ReactNode[] = [];
    if (meta?.protocol) extras.push(getProtocolLabel(meta.protocol));
    return {
      id: '__surface__',
      icon: def.paletteIcon,
      color: def.color,
      typeLabel: def.label,
      name: meta?.name?.trim() || 'Untitled Surface',
      description: def.description ?? '',
      configured: faultReason === null,
      faultReason,
      extras,
    };
  })();

  const rows = nodes
    .map(node => resolveRow(node, surfacePolicyIds))
    .filter((r): r is RowInfo => r !== null)
    // Stable, useful ordering: ingress → middleware → target → egress → decorative.
    .sort((a, b) => a.typeLabel.localeCompare(b.typeLabel));

  // Surface always appears first regardless of alphabetical sort.
  if (surfaceRow) rows.unshift(surfaceRow);

  if (rows.length === 0) {
    return (
      <div
        className="card shadow-sm mb-0"
        style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}
      >
        <div className="card-header">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-list me-2"></i> Elements
          </h6>
        </div>
        <div className="card-body" style={{ flex: '1 1 auto', minHeight: 0, overflow: 'auto' }}>
          <div className="text-muted text-center py-5">
            <i className="fas fa-shapes fa-2x mb-2 d-block" />
            No elements on the surface yet — drop one onto the canvas to begin.
          </div>
        </div>
      </div>
    );
  }

  // Maximum number of extra cells across all rows; columns are unlabeled
  // because their meaning differs by element type.
  const extraColCount = rows.reduce((max, r) => Math.max(max, r.extras.length), 0);

  return (
    <div
      className="card shadow-sm mb-0 surface-elements-list"
      style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}
    >
      <div className="card-header py-2">
        <div className="d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary" style={{ fontSize: '0.85rem' }}>
            <i className="fas fa-list me-2"></i> Elements
            <span className="badge text-bg-secondary ms-2">{rows.length}</span>
          </h6>
        </div>
      </div>
      <div className="card-body p-2" style={{ flex: '1 1 auto', minHeight: 0, overflow: 'auto' }}>
        <div className="table-responsive">
          <table className="table table-hover table-sm align-middle mb-0">
            <thead>
              <tr>
                <th style={{ width: 24 }} />
                <th>Name</th>
                <th>Type</th>
                <th>Description</th>
                {Array.from({ length: extraColCount }).map((_, i) => (
                  <th key={i} />
                ))}
                <th style={{ width: 88 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => {
                return (
                  <tr
                    key={r.id}
                    onClick={onSelectNode ? () => onSelectNode(r.id) : undefined}
                    style={onSelectNode ? { cursor: 'pointer' } : undefined}
                  >
                    <td>
                      <i
                        className={`fas ${r.icon ?? 'fa-circle'}`}
                        style={{ color: r.color, fontSize: 12 }}
                      />
                    </td>
                    <td className="fw-semibold text-nowrap">{r.name}</td>
                    <td className="text-nowrap">
                      <span className="badge text-bg-secondary">{r.typeLabel}</span>
                    </td>
                    <td className="text-muted">{r.description}</td>
                    {Array.from({ length: extraColCount }).map((_, i) => (
                      <td key={i}>{r.extras[i] ?? <span className="text-muted">—</span>}</td>
                    ))}
                    <td>
                      {r.configured ? (
                        <span className="badge text-bg-success text-nowrap">
                          <i className="fas fa-check me-1" />
                          Configured
                        </span>
                      ) : (
                        <span
                          className="badge text-bg-warning text-nowrap"
                          title={r.faultReason ?? ''}
                        >
                          <i className="fas fa-exclamation-triangle me-1" />
                          Incomplete
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ElementsListTab;
