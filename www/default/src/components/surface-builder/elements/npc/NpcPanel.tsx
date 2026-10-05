import React from 'react';
import { Form } from 'react-bootstrap';
import { registry } from '../registry';
import type { ConfigPanelProps } from '../types';
import FieldHelp from '../../../shared/FieldHelp';

const NpcPanel: React.FC<ConfigPanelProps> = ({ node, config, updateField, allNodes }) => {
  // Inject `connected_to` default from parentId (preserves legacy behavior).
  const effectiveConfig = { ...config, connected_to: config.connected_to ?? node.parentId ?? '' };
  const currentNodeId = node.id;

  // Available connection targets: any node that isn't the current NPC or the surface
  const connectableNodes = (allNodes || []).filter(
    n => n.id !== currentNodeId && n.type !== 'surface'
  );

  return (
    <>
      <div className="config-section">
        <label>NPC Details</label>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">URL / Endpoint (optional)</Form.Label>
            <FieldHelp testId="field-help-npc-url-endpoint" ariaLabel="About URL / Endpoint">
              Optional: if this actor has a real address (e.g. a webhook this diagram represents),
              enter it here for your own reference. This is documentation only; the gateway doesn't
              call or validate this URL.
            </FieldHelp>
          </div>
          <Form.Control
            size="sm"
            type="text"
            placeholder="https://..."
            value={effectiveConfig.npc_url || ''}
            onChange={e => updateField('npc_url', e.target.value)}
          />
        </Form.Group>
      </div>
      <div className="config-section">
        <label>Connection</label>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">Connected To</Form.Label>
            <FieldHelp testId="field-help-npc-connected-to" ariaLabel="About Connected To">
              Choose which other element on the canvas this actor connects to with an arrow (purely
              visual, for documenting your architecture). It doesn't change how the gateway actually
              routes traffic. Default: the element you dropped this actor onto.
            </FieldHelp>
          </div>
          <Form.Select
            size="sm"
            value={effectiveConfig.connected_to || ''}
            onChange={e => updateField('connected_to', e.target.value)}
          >
            <option value="">None (free-floating)</option>
            {connectableNodes.map(n => (
              <option key={n.id} value={n.id}>
                {n.label || registry.get(n.type)?.label || n.type}
              </option>
            ))}
          </Form.Select>
        </Form.Group>
        <Form.Group className="mb-2">
          <div className="d-flex align-items-center gap-1 mb-1">
            <Form.Label className="small text-muted mb-0">Arrow Direction</Form.Label>
            <FieldHelp testId="field-help-npc-arrow-direction" ariaLabel="About Arrow Direction">
              Pick which way the arrow points: Outbound if the connected element initiates contact
              with this actor, Inbound if this actor initiates contact with it. Like the connection
              itself, this only affects how the diagram reads; it has no effect on actual gateway
              behavior.
            </FieldHelp>
          </div>
          <Form.Select
            size="sm"
            value={effectiveConfig.connection_direction || 'outbound'}
            onChange={e => updateField('connection_direction', e.target.value)}
          >
            <option value="outbound">Outbound (parent → this)</option>
            <option value="inbound">Inbound (this → parent)</option>
          </Form.Select>
        </Form.Group>
      </div>
    </>
  );
};

export default NpcPanel;
