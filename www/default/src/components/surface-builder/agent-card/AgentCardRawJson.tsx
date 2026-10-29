import React, { useMemo, useState } from 'react';
import { CopyButton } from '../../shared/CopyButton';
import { showToast } from '../../../utils/toaster';
import type { CardJson } from '../../../utils/agentCardPreview';
import { MANAGED_CARD_TITLE, SERVED_CARD_TITLE } from './AgentCardCompare';

export interface RawCardPanel {
  card: CardJson | null;
  missing?: string;
  note?: string;
}

interface AgentCardRawJsonProps {
  managed: RawCardPanel | null;
  served: RawCardPanel;
  defaultOpen?: boolean;
}

const PANEL_ID = 'agent-card-raw-panel';

const copyError = () => showToast('error', 'Could not copy to the clipboard.');

const RawSection: React.FC<{ side: 'before' | 'after'; title: string; panel: RawCardPanel }> = ({
  side,
  title,
  panel,
}) => {
  const text = useMemo(
    () => (panel.card ? JSON.stringify(panel.card, null, 2) : null),
    [panel.card]
  );
  const titleId = `agent-card-raw-${side}-title`;
  return (
    <div className="agent-card-raw-section" data-testid={`agent-card-raw-${side}-section`}>
      <div className="agent-card-raw-heading">
        <h3 id={titleId}>{title}</h3>
        {text !== null && (
          <CopyButton
            text={text}
            variant="outline-primary"
            label="Copy"
            title={`Copy the ${title} JSON`}
            aria-label={`Copy the ${title} JSON`}
            className="ms-0"
            data-testid={`agent-card-copy-${side}-button`}
            onCopyError={copyError}
          />
        )}
      </div>
      {panel.note && (
        <p className="agent-card-raw-note" data-testid={`agent-card-raw-${side}-note`}>
          {panel.note}
        </p>
      )}
      {text !== null ? (
        <pre
          className="agent-card-json"
          role="region"
          tabIndex={0}
          aria-labelledby={titleId}
          data-testid={`agent-card-raw-${side}`}
        >
          {text}
        </pre>
      ) : (
        <p className="agent-card-raw-missing" data-testid={`agent-card-raw-${side}-missing`}>
          {panel.missing ?? 'Not available.'}
        </p>
      )}
    </div>
  );
};

const AgentCardRawJson: React.FC<AgentCardRawJsonProps> = ({
  managed,
  served,
  defaultOpen = false,
}) => {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="agent-card-raw">
      <button
        type="button"
        className="btn btn-outline-secondary btn-sm"
        aria-expanded={open}
        aria-controls={PANEL_ID}
        onClick={() => setOpen(o => !o)}
        data-testid="agent-card-raw-toggle"
      >
        <i className={`fas fa-chevron-${open ? 'down' : 'right'} me-2`} aria-hidden="true" />
        {open ? 'Hide raw JSON' : 'Show raw JSON'}
      </button>
      {open && (
        <div id={PANEL_ID} className="agent-card-raw-panels">
          {managed && <RawSection side="before" title={MANAGED_CARD_TITLE} panel={managed} />}
          <RawSection side="after" title={SERVED_CARD_TITLE} panel={served} />
        </div>
      )}
    </div>
  );
};

export default AgentCardRawJson;
