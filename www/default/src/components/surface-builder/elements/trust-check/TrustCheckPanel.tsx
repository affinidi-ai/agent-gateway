import React from 'react';
import { Form } from 'react-bootstrap';
import { AppButton } from '../../../shared/AppButton';
import { findSlotById } from '../edges/archetypes';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { readQueries, type TrustCheckRecordType } from './definition';

const PREVIEW_MAX = 5;

interface TrustCheckLegContext {
  title: string;
  summary: string;
  where: string;
  when: string;
  example: string;
}

function describeLeg(isApMa: boolean): TrustCheckLegContext {
  if (isApMa) {
    return {
      title: 'How can you trust the sender of an incoming request using Trust Check?',
      summary:
        'Verify the CALLER identity against a trust registry before the request reaches the agent.',
      where: 'Access Point → Managed Agent (request leg).',
      when: 'When policy needs to know that the caller is recognised or authorised by an authority in a trust registry (e.g. only accept requests from agents recognised by a partner ecosystem).',
      example:
        'Pick the trust anchor to check against: an Issuer (Department) or an Authority. Its DID is stored directly, so the gateway never derives the authority from the caller’s request payload.',
    };
  }
  return {
    title: 'How can you trust a destination entity before sending requests using Trust Check?',
    summary: 'Verify the TARGET identity (upstream agent) before the request leaves the gateway.',
    where: 'Managed Agent → Transit Point (target leg).',
    when: 'When policy needs to confirm the upstream you are about to call is recognised or authorised (e.g. only forward payment requests to issuers recognised by a payment authority).',
    example:
      'Pick the trust anchor to check against: an Issuer (Department) or an Authority. Its DID is stored directly, so the gateway never derives the authority from the target’s own agent card.',
  };
}

const TrustCheckPanel: React.FC<ConfigPanelProps> = ({ node, config, openFullscreenEditor }) => {
  const slotId = node.slotId || '';
  const resolved = slotId ? findSlotById(slotId) : undefined;
  const isApMa = resolved?.archetype.id === 'ap-ma' || config._edge === 'ap-ma';
  const legLabel = isApMa ? 'caller' : 'target';
  const legContext = describeLeg(isApMa);
  const queries = readQueries(config);
  const shown = queries.slice(0, PREVIEW_MAX);
  const remaining = queries.length - shown.length;
  const renderEmptyState = () => (
    <div className="py-2 text-center" data-testid="trust-check-panel-empty-state">
      <div className="fw-semibold small mb-2" style={{ fontSize: '12px' }}>
        <i
          className="fas fa-certificate me-2 text-muted"
          style={{ opacity: 0.6 }}
          aria-hidden="true"
        />
        No trust checks yet
      </div>
      <Form.Text className="d-block text-muted mb-2 mx-4 text-center" style={{ fontSize: '11px' }}>
        Configure queries to have OPA verify the {isApMa ? 'caller' : 'upstream agent'} against a
        trust registry before the request {isApMa ? 'reaches the agent' : 'leaves the gateway'}.
      </Form.Text>
    </div>
  );

  const renderQueriesList = () => (
    <div data-testid="trust-check-panel-list">
      <div className="fw-bold small text-muted mb-1" style={{ fontSize: '12px' }}>
        Queries
      </div>
      <ul className="list-unstyled mb-2" style={{ fontSize: '11px' }}>
        {shown.map((q, idx) => {
          const queryType: TrustCheckRecordType =
            q.query_type === 'recognition' ? 'recognition' : 'authorization';
          const typeLabel = queryType === 'recognition' ? 'Recognition' : 'Authorization';
          const nameValue = typeof q.name === 'string' && q.name ? q.name : '';
          return (
            <li
              key={q.id || `idx-${idx}`}
              className="d-flex justify-content-between align-items-baseline gap-2 py-1"
            >
              <span className="text-muted fw-semibold">Query {idx + 1}</span>
              <span
                className="text-end"
                style={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  minWidth: 0,
                }}
              >
                <span className="fw-semibold">{typeLabel}</span>
                {nameValue && (
                  <span
                    className="d-block text-muted fst-italic"
                    style={{
                      fontSize: '10px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={nameValue}
                  >
                    {nameValue}
                  </span>
                )}
              </span>
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
          data-testid="trust-check-panel-results-ref"
        >
          Results land on OPA at <code>input.trust_check_results.{legLabel}[]</code>: OPA decides
          allow / deny.
        </Form.Text>
      </div>

      <InfoBanner
        title={legContext.title}
        icon="fa-certificate"
        testIdPrefix="trust-check-panel"
        summary={legContext.summary}
      >
        <dl>
          <dt>Where</dt>
          <dd>{legContext.where}</dd>
          <dt>When</dt>
          <dd>{legContext.when}</dd>
          <dt>Example</dt>
          <dd style={{ fontStyle: 'italic' }}>{legContext.example}</dd>
        </dl>
      </InfoBanner>

      <div className="config-section">
        {queries.length === 0 ? renderEmptyState() : renderQueriesList()}

        <AppButton
          variant="primary"
          size="sm"
          className="w-100 mt-2"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
          iconStart={<i className="fas fa-pen-to-square me-1" aria-hidden="true" />}
          data-testid="trust-check-panel-configure"
        >
          Configure Queries…
        </AppButton>
      </div>
    </>
  );
};

export default TrustCheckPanel;
