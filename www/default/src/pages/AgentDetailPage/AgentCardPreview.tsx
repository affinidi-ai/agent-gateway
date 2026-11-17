import React, { useState } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { VpView } from '../../components/shared/VpViewer';
import { UNNAMED_AGENT } from '../AgentsPage/agentLabels';
import { GatewayChanges, IDENTITY_CREDENTIAL_EXTENSION, gatewayChanges } from './gatewayChanges';

type CardFields = Record<string, unknown>;

const isObject = (value: unknown): value is CardFields =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): string | null => {
  if (typeof value === 'number') return String(value);
  return typeof value === 'string' && value.trim() ? value.trim() : null;
};

const textList = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(text).filter((v): v is string => v !== null) : [];

const NotSet: React.FC = () => <span className="text-muted">Not set</span>;

interface Skill {
  key: string;
  name: string;
  description: string | null;
}

const skillsOf = (card: CardFields): Skill[] =>
  Array.isArray(card.skills)
    ? card.skills.filter(isObject).map((skill, index) => ({
        key: `${index}-${text(skill.id) ?? ''}`,
        name: text(skill.name) ?? text(skill.id) ?? `Skill ${index + 1}`,
        description: text(skill.description),
      }))
    : [];

const Value: React.FC<{ value: string | null }> = ({ value }) =>
  value === null ? (
    <span className="text-muted">-</span>
  ) : (
    <code className="small text-break fw-semibold">{value}</code>
  );

type ChangeKind = 'rewritten' | 'added' | 'removed';

const CHANGE_BADGES: Record<ChangeKind, { label: string; className: string }> = {
  rewritten: { label: 'Rewritten', className: 'text-bg-warning' },
  added: { label: 'Added', className: 'text-bg-primary' },
  removed: { label: 'Removed', className: 'text-bg-secondary' },
};

interface ChangeRow {
  key: string;
  field: string;
  kind: ChangeKind;
  testid: string;
  value: React.ReactNode;
  /** The value before the gateway changed it; `null` when there is nothing worth showing. */
  was: string | null;
  /** The presentation the row's Show button expands across the table. */
  vp?: string;
}

const kindOf = (before: unknown, after: unknown): ChangeKind => {
  if (before === null || before === false) return 'added';
  return after === null ? 'removed' : 'rewritten';
};

const changeRows = (changes: GatewayChanges): ChangeRow[] => {
  const rows: ChangeRow[] = [];
  if (changes.url) {
    rows.push({
      key: 'url',
      field: 'URL',
      kind: kindOf(changes.url.upstream, changes.url.served),
      testid: 'agent-card-gateway-url',
      value: <Value value={changes.url.served} />,
      was: changes.url.upstream,
    });
  }
  changes.added.forEach((extension, index) => {
    const key = `${extension.uri}-${index}`;
    rows.push({
      key,
      field: extension.uri === IDENTITY_CREDENTIAL_EXTENSION ? 'Identity credential' : 'Extension',
      kind: kindOf(extension.original, extension.uri),
      testid: 'agent-card-gateway-extension',
      value: <Value value={extension.uri} />,
      was: extension.original === extension.uri ? null : extension.original,
    });
    if ((extension.did || extension.originalDid) && extension.did !== extension.originalDid) {
      rows.push({
        key: `${key}-did`,
        field: 'DID',
        kind: kindOf(extension.originalDid, extension.did),
        testid: 'agent-card-gateway-did',
        value: <Value value={extension.did} />,
        was: extension.originalDid,
      });
    }
    if (extension.vp) {
      rows.push({
        key: `${key}-vp`,
        field: 'Verifiable Presentation',
        kind: kindOf(extension.originalHasVp, extension.vp),
        testid: 'agent-card-gateway-vp',
        value: null,
        was: null,
        vp: extension.vp,
      });
    }
  });
  changes.removed.forEach(uri =>
    rows.push({
      key: `removed-${uri}`,
      field: 'Extension',
      kind: 'removed',
      testid: 'agent-card-gateway-removed',
      value: <Value value={null} />,
      was: uri,
    })
  );
  changes.otherFields.forEach(change =>
    rows.push({
      key: `field-${change.field}`,
      field: change.field,
      kind: kindOf(change.original, change.rewritten),
      testid: `agent-card-gateway-other-${change.field}`,
      value: <Value value={change.rewritten} />,
      was: change.original,
    })
  );
  return rows;
};

/** One change. A presentation's Show button expands it in a full-width row under its own. */
const ChangeRowView: React.FC<{ row: ChangeRow }> = ({ row }) => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr>
        <td className="agent-preview-change-field">{row.field}</td>
        <td>
          <span
            className={`badge ${CHANGE_BADGES[row.kind].className}`}
            data-testid={`${row.testid}-change`}
          >
            {CHANGE_BADGES[row.kind].label}
          </span>
        </td>
        <td>
          <div data-testid={row.testid}>
            {row.vp !== undefined ? (
              <AppButton
                variant="outline-secondary"
                size="sm"
                onClick={() => setOpen(o => !o)}
                aria-expanded={open}
                iconStart={
                  <i
                    className={`fas ${open ? 'fa-eye-slash' : 'fa-eye'} me-1`}
                    aria-hidden="true"
                  />
                }
                data-testid="agent-card-gateway-vp-toggle-button"
              >
                {open ? 'Hide' : 'Show'}
              </AppButton>
            ) : (
              row.value
            )}
          </div>
          {row.was !== null && (
            <div className="text-muted small text-break" data-testid={`${row.testid}-was`}>
              Was <code className="small text-muted">{row.was}</code>
            </div>
          )}
        </td>
      </tr>
      {open && row.vp !== undefined && (
        <tr>
          <td colSpan={3} data-testid="agent-card-gateway-vp-view">
            <VpView vpJwt={row.vp} />
          </td>
        </tr>
      )}
    </>
  );
};

interface GatewayChangesSectionProps {
  changes: GatewayChanges;
  hasIdentityCredential: boolean;
}

/**
 * What the gateway changed in the card, the URL first: the value callers get, with what it was
 * under a rewritten one. Every value is plain text.
 */
const GatewayChangesSection: React.FC<GatewayChangesSectionProps> = ({
  changes,
  hasIdentityCredential,
}) => (
  <section className="agent-preview-gateway" data-testid="agent-card-gateway-changes">
    <h6 className="agent-preview-section-title">Changes by the gateway</h6>
    <table className="table table-sm align-middle mb-0 agent-preview-changes">
      <thead>
        <tr>
          <th scope="col">Field</th>
          <th scope="col">Change</th>
          <th scope="col">Value</th>
        </tr>
      </thead>
      <tbody>
        {changeRows(changes).map(row => (
          <ChangeRowView key={row.key} row={row} />
        ))}
      </tbody>
    </table>
    {!hasIdentityCredential && (
      <p className="text-muted small mt-2 mb-0" data-testid="agent-card-gateway-no-did">
        This surface has no DID, so the card carries no identity credential.
      </p>
    )}
  </section>
);

interface AgentCardPreviewProps {
  card: unknown;
  /** The card before the gateway rewrote it, when the API returns one. */
  upstreamCard?: unknown;
}

/**
 * A visual summary of the card the gateway serves, its skills, then what the gateway changed. The
 * card is untrusted, so every value renders as plain text: no HTML, Markdown or links, and the
 * URL is not clickable.
 */
const AgentCardPreview: React.FC<AgentCardPreviewProps> = ({ card, upstreamCard }) => {
  if (!isObject(card)) {
    return (
      <p className="text-muted mb-0" data-testid="agent-card-preview-empty">
        This card isn&apos;t a JSON object, so there is nothing to preview. Switch to JSON to see
        it.
      </p>
    );
  }

  const name = text(card.name);
  const description = text(card.description);
  const url = text(card.url);
  const provider = isObject(card.provider) ? text(card.provider.organization) : null;
  const streaming = isObject(card.capabilities) ? card.capabilities.streaming : undefined;
  const inputModes = textList(card.defaultInputModes);
  const outputModes = textList(card.defaultOutputModes);
  const skills = skillsOf(card);
  const changes = gatewayChanges(card, upstreamCard);
  const hasIdentityCredential =
    isObject(card.capabilities) &&
    Array.isArray(card.capabilities.extensions) &&
    card.capabilities.extensions.some(
      extension => isObject(extension) && extension.uri === IDENTITY_CREDENTIAL_EXTENSION
    );

  const rows: { label: string; value: React.ReactNode }[] = [
    { label: 'Version', value: text(card.version) ?? <NotSet /> },
    { label: 'Provider', value: provider ?? <NotSet /> },
    ...(changes?.url
      ? []
      : [{ label: 'URL', value: url ? <code className="small">{url}</code> : <NotSet /> }]),
    { label: 'Protocol version', value: text(card.protocolVersion) ?? <NotSet /> },
    {
      label: 'Streaming',
      value: typeof streaming === 'boolean' ? streaming ? 'Yes' : 'No' : <NotSet />,
    },
    { label: 'Input modes', value: inputModes.length ? inputModes.join(', ') : <NotSet /> },
    { label: 'Output modes', value: outputModes.length ? outputModes.join(', ') : <NotSet /> },
  ];

  return (
    <div className="agent-preview" data-testid="agent-card-preview">
      <div className="agent-preview-head">
        <span className="agent-preview-avatar">
          <i className="fas fa-robot" aria-hidden="true" />
        </span>
        <div className="agent-preview-title">
          <div className="agent-preview-name" data-testid="agent-card-preview-name">
            {name ?? <span className="fst-italic">{UNNAMED_AGENT}</span>}
          </div>
          <div className="agent-preview-description">
            {description ?? <span className="fst-italic">No description</span>}
          </div>
        </div>
      </div>
      <dl className="agent-preview-rows" data-testid="agent-card-preview-details">
        {rows.map(row => (
          <React.Fragment key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </React.Fragment>
        ))}
      </dl>
      <section className="agent-preview-skills" data-testid="agent-card-preview-skills">
        <h6 className="agent-preview-skills-title">Skills ({skills.length})</h6>
        {skills.length === 0 ? (
          <span className="text-muted">No skills listed</span>
        ) : (
          <ul className="agent-preview-skill-list">
            {skills.map(skill => (
              <li key={skill.key}>
                <div className="fw-semibold">{skill.name}</div>
                {skill.description && (
                  <div className="agent-preview-skill-description">{skill.description}</div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      {changes && (
        <GatewayChangesSection changes={changes} hasIdentityCredential={hasIdentityCredential} />
      )}
    </div>
  );
};

export default AgentCardPreview;
