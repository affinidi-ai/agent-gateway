import React from 'react';
import { Form } from 'react-bootstrap';
import { AppButton } from '../../../shared/AppButton';
import AddResourceLink from '../../../shared/AddResourceLink';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { deepLinks } from '../../../../utils/deepLinks';
import { readEntries, TRUST_RECORDER_ENTRIES_MAX } from './definition';

const PREVIEW_MAX = 5;

interface TrustRecorderContext {
  title: string;
  summary: string;
  where: string;
  when: string;
  example: string;
}

function describeContext(): TrustRecorderContext {
  return {
    title:
      'How does Trust Recorder make your managed agents discoverable for recognition and authorization?',
    summary:
      'Write agent-registration records into one or more Trust Registries on the response leg so the agent becomes discoverable and verifiable by future callers.',
    where: 'Managed Agent → Access Point (response leg).',
    when: 'When a managed agent should be announced to a trust registry — e.g. publish the agent as an `ownedAgent` of its provider so partner ecosystems can recognise it on later requests.',
    example:
      'Built-in triple: authority = authority DID, entity = agent DID (auto-filled from the response), action = `is`, resource = `ownedAgent`. Set the Authority to the surface\'s Issuer (option: "Use surface Issuer") to have records match the downstream Trust Check `authority = verified identity credential issuer` query.',
  };
}

const TrustRecorderPanel: React.FC<ConfigPanelProps> = ({ config, openFullscreenEditor }) => {
  const entries = readEntries(config);
  const shown = entries.slice(0, PREVIEW_MAX);
  const remaining = entries.length - shown.length;
  const context = describeContext();
  const renderEmptyState = () => (
    <div className="py-2 text-center" data-testid="trust-recorder-panel-empty-state">
      <div className="fw-semibold small mb-2" style={{ fontSize: '12px' }}>
        <i
          className="fas fa-pen-to-square me-2 text-muted"
          style={{ opacity: 0.6 }}
          aria-hidden="true"
        />
        No registries yet
      </div>
      <Form.Text className="d-block text-muted mb-2 mx-4 text-center" style={{ fontSize: '11px' }}>
        Configure at least one Trust Registry to have the gateway record the agent&apos;s identity
        on the response leg.{' '}
        <AddResourceLink
          to={deepLinks.trustRegistry}
          testid="trust-recorder-panel-add-registry-link"
        >
          Add Trust Registry
        </AddResourceLink>
      </Form.Text>
    </div>
  );

  const renderEntriesList = () => (
    <div data-testid="trust-recorder-panel-list">
      <div className="d-flex flex-wrap align-items-center gap-1 mb-2">
        <span
          className={`badge ${entries.length > 0 ? 'text-bg-primary' : 'text-bg-secondary'}`}
          style={{ fontSize: '10px' }}
        >
          {entries.length}/{TRUST_RECORDER_ENTRIES_MAX} registries
        </span>
      </div>
      <ul className="list-unstyled mb-2" style={{ fontSize: '11px' }}>
        {shown.map((e, idx) => {
          const triples = e.include_owned_agent ? 'ownedAgent' : '';
          const custom =
            e.custom_resources.length > 0 ? ` · +${e.custom_resources.length} custom` : '';
          return (
            <li
              key={`${e.trust_registry_id || 'na'}-${idx}`}
              className="text-muted"
              style={{
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              Entry {idx + 1} · {e.trust_registry_id || 'no registry'}
              {triples ? ` · ${triples}` : ''}
              {custom}
            </li>
          );
        })}
        {remaining > 0 && (
          <li className="text-muted fst-italic pt-1" style={{ fontSize: '11px' }}>
            +{remaining} more
          </li>
        )}
      </ul>
    </div>
  );

  return (
    <>
      <div className="config-section">
        <Form.Text
          className="text-muted d-block"
          style={{ fontSize: '11px' }}
          data-testid="trust-recorder-panel-results-ref"
        >
          Writes records to every configured Trust Registry on the <strong>response leg</strong>{' '}
          (Managed Agent &rarr; Access Point).
        </Form.Text>
      </div>

      <InfoBanner
        title={context.title}
        icon="fa-pen-to-square"
        testIdPrefix="trust-recorder-panel"
        summary={context.summary}
      >
        <dl>
          <dt>Where</dt>
          <dd>{context.where}</dd>
          <dt>When</dt>
          <dd>{context.when}</dd>
          <dt>Example</dt>
          <dd style={{ fontStyle: 'italic' }}>{context.example}</dd>
        </dl>
      </InfoBanner>

      <div className="config-section">
        {entries.length === 0 ? renderEmptyState() : renderEntriesList()}

        <AppButton
          variant="primary"
          size="sm"
          className="w-100 mt-2"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
          iconStart={<i className="fas fa-pen-to-square me-1" aria-hidden="true" />}
          data-testid="trust-recorder-panel-configure"
        >
          Configure Trust Recorder…
        </AppButton>
      </div>
    </>
  );
};

export default TrustRecorderPanel;
