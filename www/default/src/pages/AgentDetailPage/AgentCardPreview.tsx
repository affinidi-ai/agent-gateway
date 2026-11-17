import React from 'react';
import { VpJwtRow } from '../../components/shared/VpViewer';
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

/** What the gateway changed in the card, the rewritten URL first. Every value is plain text. */
const GatewayChangesSection: React.FC<{ changes: GatewayChanges }> = ({ changes }) => (
  <section className="agent-preview-gateway" data-testid="agent-card-gateway-changes">
    <h6 className="agent-preview-section-title">Added by the gateway</h6>
    <dl className="agent-preview-rows">
      {changes.url && (
        <>
          <dt>URL</dt>
          <dd data-testid="agent-card-gateway-url">
            <code className="small">{changes.url.served}</code>
            {changes.url.upstream && (
              <div className="small text-muted">
                Rewritten from <code className="small">{changes.url.upstream}</code>
              </div>
            )}
          </dd>
        </>
      )}
      {changes.added.map((extension, index) => (
        <React.Fragment key={`${extension.uri}-${index}`}>
          <dt>
            {extension.uri === IDENTITY_CREDENTIAL_EXTENSION ? 'Identity credential' : 'Extension'}
          </dt>
          <dd data-testid="agent-card-gateway-extension">
            <code className="small">{extension.uri}</code>
            {extension.did && (
              <div className="small" data-testid="agent-card-gateway-did">
                <span className="text-muted me-1">DID</span>
                <code className="small">{extension.did}</code>
              </div>
            )}
            {extension.presentation && (
              <table className="table table-sm table-borderless mb-0 mt-1">
                <tbody>
                  <VpJwtRow vpJwt={extension.presentation} />
                </tbody>
              </table>
            )}
          </dd>
        </React.Fragment>
      ))}
      {changes.replaced.length > 0 && (
        <>
          <dt>Replaces</dt>
          <dd data-testid="agent-card-gateway-replaced">
            {changes.replaced.map(uri => (
              <div key={uri}>
                <code className="small">{uri}</code>
              </div>
            ))}
          </dd>
        </>
      )}
      {changes.otherFields.length > 0 && (
        <>
          <dt>Also changed</dt>
          <dd data-testid="agent-card-gateway-other">{changes.otherFields.join(', ')}</dd>
        </>
      )}
    </dl>
  </section>
);

interface AgentCardPreviewProps {
  card: unknown;
  /** The card before the gateway rewrote it, when the API returns one. */
  upstreamCard?: unknown;
}

/**
 * A visual summary of the card the gateway serves, then what the gateway changed in it. The
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

  const rows: { label: string; value: React.ReactNode }[] = [
    { label: 'Version', value: text(card.version) ?? <NotSet /> },
    { label: 'Provider', value: provider ?? <NotSet /> },
    { label: 'URL', value: url ? <code className="small">{url}</code> : <NotSet /> },
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
      <dl className="agent-preview-rows">
        {rows.map(row => (
          <React.Fragment key={row.label}>
            <dt>{row.label}</dt>
            <dd>{row.value}</dd>
          </React.Fragment>
        ))}
      </dl>
      {changes && <GatewayChangesSection changes={changes} />}
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
    </div>
  );
};

export default AgentCardPreview;
