import React, { useMemo } from 'react';
import {
  cardEra,
  diffAgentCards,
  type CardEra,
  type DiffItem,
  type DiffRow,
  type ItemStatus,
} from '../../../utils/agentCardDiff';
import type { CardJson } from '../../../utils/agentCardPreview';
import { Badge } from '../../shared/Badge';

type TagStatus = ItemStatus | 'absent';
type Side = 'before' | 'after';

const ERA_LABEL: Record<CardEra, string> = {
  '1.0': 'A2A 1.0',
  '0.3': 'A2A 0.3',
  both: 'A2A 0.3 and 1.0',
  unknown: 'Format unknown',
};

const TAG_LABEL: Record<TagStatus, string> = {
  same: 'Unchanged',
  added: 'Added',
  changed: 'Modified',
  removed: 'Removed',
  absent: 'None',
};

const TAG_ICON: Record<TagStatus, string> = {
  same: 'fa-equals',
  added: 'fa-plus',
  changed: 'fa-pen',
  removed: 'fa-minus',
  absent: 'fa-ellipsis',
};

const LEGEND: ReadonlyArray<TagStatus> = ['added', 'changed', 'removed', 'same'];

export const MANAGED_CARD_TITLE = 'Managed Agent Card';
export const SERVED_CARD_TITLE = 'Gateway-Served Agent Card';

const StatusTag: React.FC<{ status: TagStatus; testId?: string }> = ({ status, testId }) => (
  <span
    className={`agent-card-status agent-card-status-${status}`}
    data-status={status}
    data-testid={testId}
  >
    <i
      className={`fas ${TAG_ICON[status]}`}
      aria-hidden="true"
      data-testid="agent-card-status-icon"
    />
    {TAG_LABEL[status]}
  </span>
);

function itemTag(status: ItemStatus, side: Side): TagStatus | null {
  if (status === 'changed') return 'changed';
  if (status === 'removed' && side === 'before') return 'removed';
  if (status === 'added' && side === 'after') return 'added';
  return null;
}

const CellItem: React.FC<{ item: DiffItem; side: Side; showStatus: boolean }> = ({
  item,
  side,
  showStatus,
}) => {
  const value = side === 'before' ? item.before : item.after;
  const tag = showStatus ? itemTag(item.status, side) : null;
  return (
    <li
      className={`agent-card-item${tag ? ` agent-card-item-${tag}` : ''}`}
      data-status={item.status}
    >
      <span className="agent-card-item-label">
        {item.label}
        {item.primary && <span className="text-muted"> (primary)</span>}
      </span>
      {value === null ? (
        <span className="text-muted agent-card-item-value">Not present</span>
      ) : (
        value !== item.label && <code className="agent-card-item-value">{value}</code>
      )}
      {tag && <StatusTag status={tag} />}
    </li>
  );
};

const CellItems: React.FC<{ row: DiffRow; side: Side; showStatus: boolean }> = ({
  row,
  side,
  showStatus,
}) => {
  if (row.items.length === 0) return <span className="text-muted">None</span>;
  const shown = row.key === 'other' ? row.items.filter(i => i.status !== 'same') : row.items;
  const unchanged = row.items.length - shown.length;
  return (
    <>
      {shown.length > 0 && (
        <ul className="agent-card-items">
          {shown.map(item => (
            <CellItem key={item.path} item={item} side={side} showStatus={showStatus} />
          ))}
        </ul>
      )}
      {unchanged > 0 && (
        <span className="text-muted small">
          {unchanged} unchanged {unchanged === 1 ? 'part' : 'parts'}
        </span>
      )}
    </>
  );
};

const ColumnHeading: React.FC<{ title: string; hint: string; era: CardEra; side: Side }> = ({
  title,
  hint,
  era,
  side,
}) => (
  <th scope="col" data-testid={`agent-card-${side}`}>
    <span className="agent-card-column-title">{title}</span>
    <span className="agent-card-column-hint">{hint}</span>
    <Badge value={ERA_LABEL[era]} tone="secondary" data-testid={`agent-card-era-${side}`} />
  </th>
);

const Summary: React.FC<{
  changeCount: number;
  addedCount: number;
  modifiedCount: number;
  removedCount: number;
}> = ({ changeCount, addedCount, modifiedCount, removedCount }) => (
  <div className="agent-card-summary" data-testid="agent-card-summary" aria-live="polite">
    <i className="fas fa-circle-info" aria-hidden="true" />
    <span>
      {changeCount === 0 ? (
        "The gateway serves the agent's card unchanged."
      ) : (
        <>
          The gateway changed <strong data-testid="agent-card-change-count">{changeCount}</strong>{' '}
          {changeCount === 1 ? 'part' : 'parts'} of the card: {addedCount} added, {modifiedCount}{' '}
          modified, {removedCount} removed.
        </>
      )}
    </span>
  </div>
);

interface AgentCardCompareProps {
  before: CardJson | null;
  after: CardJson;
  generated: boolean;
}

const AgentCardCompare: React.FC<AgentCardCompareProps> = ({ before, after, generated }) => {
  const diff = useMemo(
    () => diffAgentCards(generated ? after : before, after),
    [before, after, generated]
  );
  const beforeEra = useMemo(() => cardEra(before), [before]);
  const afterEra = useMemo(() => cardEra(after), [after]);

  return (
    <div className="agent-card-compare">
      {!generated && (
        <>
          <Summary
            changeCount={diff.changeCount}
            addedCount={diff.addedCount}
            modifiedCount={diff.modifiedCount}
            removedCount={diff.removedCount}
          />
          <ul className="agent-card-legend" data-testid="agent-card-legend" aria-label="Legend">
            {LEGEND.map(status => (
              <li key={status}>
                <StatusTag status={status} testId={`agent-card-legend-${status}`} />
              </li>
            ))}
          </ul>
        </>
      )}
      <div className="agent-card-table-wrap">
        <table className="agent-card-table">
          <caption className="visually-hidden">
            {generated
              ? `The ${SERVED_CARD_TITLE}`
              : `The ${MANAGED_CARD_TITLE} beside the ${SERVED_CARD_TITLE}`}
          </caption>
          <thead>
            <tr>
              <th scope="col">
                <span className="visually-hidden">Part of the card</span>
              </th>
              {!generated && (
                <ColumnHeading
                  title={MANAGED_CARD_TITLE}
                  hint="The agent's own card"
                  era={beforeEra}
                  side="before"
                />
              )}
              <ColumnHeading
                title={SERVED_CARD_TITLE}
                hint="What callers see"
                era={afterEra}
                side="after"
              />
            </tr>
          </thead>
          <tbody>
            {diff.rows.map(row => (
              <tr
                key={row.key}
                data-testid={`agent-card-row-${row.key}`}
                data-status={generated ? undefined : row.status}
              >
                <th scope="row">
                  <span className="agent-card-row-label">{row.label}</span>
                  {!generated && <StatusTag status={row.status} />}
                </th>
                {!generated && (
                  <td data-label={MANAGED_CARD_TITLE}>
                    <CellItems row={row} side="before" showStatus />
                  </td>
                )}
                <td data-label={SERVED_CARD_TITLE}>
                  <CellItems row={row} side="after" showStatus={!generated} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AgentCardCompare;
