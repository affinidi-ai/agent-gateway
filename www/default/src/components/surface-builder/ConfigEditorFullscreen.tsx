import React from 'react';
import type { CanvasNode } from './SurfaceCanvas';
import type { SurfaceNodeType } from './nodeTypes';
import { registry, buildSurfaceContext } from './elements';
import { shouldShowDependencyWarnings } from './dependencyWarningVisibility';

interface ConfigEditorFullscreenProps {
  node: CanvasNode | null;
  protocol?: string;
  allNodes?: CanvasNode[];
  onUpdate: (nodeId: string, config: any) => void;
  /** Called when the user re-requests fullscreen from inside (no-op here, but kept for API symmetry). */
  onOpenFullscreenEditor?: (nodeId: string) => void;
  /** Close the editor tab and return to the canvas. */
  onCloseFullscreenEditor?: () => void;
  /** Show dependency warnings only after the first page-level Save attempt. */
  hasAttemptedSave?: boolean;
}

/**
 * Fullscreen editor body, rendered inside the surface-builder editor tab.
 * Picks the element's `FullscreenPanel` if defined, otherwise falls back to
 * its `ConfigPanel`. The tab chrome (header, "Done" button) is owned by the
 * wizard, so this component only renders the editor body.
 */
const ConfigEditorFullscreen: React.FC<ConfigEditorFullscreenProps> = ({
  node,
  protocol,
  allNodes,
  onUpdate,
  onCloseFullscreenEditor,
  hasAttemptedSave = false,
}) => {
  if (!node) return null;
  const def = registry.get(node.type as SurfaceNodeType);
  if (!def) return null;
  const Panel = def.FullscreenPanel ?? def.ConfigPanel;
  if (!Panel) return null;

  const updateField = (field: string, value: any) => {
    onUpdate(node.id, { ...node.config, [field]: value });
  };
  const updateFields = (fields: Record<string, any>) => {
    onUpdate(node.id, { ...node.config, ...fields });
  };

  const ctx = buildSurfaceContext(protocol, allNodes);
  const warnings = registry.getDependencyWarnings(node.type, node.config, ctx);

  return (
    <div className="surface-builder-fullscreen-body">
      {warnings.length > 0 && shouldShowDependencyWarnings(node.type, hasAttemptedSave) && (
        <div className="mb-3">
          {warnings.map((w, i) => (
            <div
              key={i}
              className={`alert alert-${w.severity === 'error' ? 'danger' : 'warning'} py-2 px-3 mb-2`}
            >
              <i
                className={`fas fa-${w.severity === 'error' ? 'times-circle' : 'exclamation-triangle'} me-2`}
              />
              {w.message}
            </div>
          ))}
        </div>
      )}
      <Panel
        node={node}
        config={node.config || {}}
        updateField={updateField}
        updateFields={updateFields}
        protocol={protocol as any}
        allNodes={allNodes}
        closeFullscreenEditor={onCloseFullscreenEditor}
        hasAttemptedSave={hasAttemptedSave}
      />
    </div>
  );
};

export default ConfigEditorFullscreen;
