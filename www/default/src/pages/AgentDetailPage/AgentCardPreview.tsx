import React from 'react';
import { UNNAMED_AGENT } from '../AgentsPage/agentLabels';

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

/**
 * A visual summary of the agent's published card. The card is untrusted, so every
 * value renders as plain text: no HTML, Markdown or links, and the URL is not clickable.
 */
const AgentCardPreview: React.FC<{ card: unknown }> = ({ card }) => {
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
      <div className="agent-preview-eyebrow">Agent Card</div>
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
      <div className="agent-preview-footer" data-testid="agent-card-preview-skills">
        <div className="fw-semibold mb-1">Skills ({skills.length})</div>
        {skills.length === 0 ? (
          <span>No skills listed</span>
        ) : (
          <ul className="list-unstyled mb-0">
            {skills.map(skill => (
              <li key={skill.key} className="mb-1">
                <strong>{skill.name}</strong>
                {skill.description && <span className="ms-2">{skill.description}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default AgentCardPreview;
