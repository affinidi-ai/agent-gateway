import React from 'react';
import { Form } from 'react-bootstrap';
import { AppButton } from '../../../shared/AppButton';
import { managedAgentTargetLegTrustCheckAllowed } from '../edges/archetypes';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import MigratedTrustCheckWarning from './MigratedTrustCheckWarning';
import {
  MANAGED_AGENT_TRUST_CHECK_DUPLICATED_NOTE,
  managedAgentTrustCheckRunsOnTransitPoints,
  readOnlyTrustCheckMessage,
  readOnlyTrustCheckProtocol,
  isManagedAgentTrustCheck,
  isMigratedTrustCheck,
  readQueries,
  trustCheckLeg,
  type TrustCheckLeg,
  type TrustCheckRecordType,
} from './definition';

const PREVIEW_MAX = 5;

interface TrustCheckLegContext {
  title: string;
  summary: string;
  where: string;
  when: string;
  example: string;
}

function describeLeg(leg: TrustCheckLeg): TrustCheckLegContext {
  if (leg === 'caller') {
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
    where:
      leg === 'transit-point'
        ? 'Managed Agent → Transit Point (target leg). Runs only for requests through this Transit Point.'
        : 'Managed Agent → its A2A Proxy or gateway target (target leg).',
    when: 'When policy needs to confirm the upstream you are about to call is recognised or authorised (e.g. only forward payment requests to issuers recognised by a payment authority).',
    example:
      'Pick the trust anchor to check against: an Issuer (Department) or an Authority. Its DID is stored directly, so the gateway never derives the authority from the target’s own agent card.',
  };
}

const TrustCheckPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  allNodes,
  updateField,
  openFullscreenEditor,
}) => {
  const leg = trustCheckLeg(node, allNodes);
  const isApMa = leg === 'caller';
  const legLabel = isApMa ? 'caller' : 'target';
  const legContext = describeLeg(leg);
  const managedAgentEndpoint = allNodes?.find(n => n.type === 'target')?.config?.endpoint;
  const notSavedForTarget =
    allNodes !== undefined &&
    isManagedAgentTrustCheck(node, allNodes) &&
    !managedAgentTargetLegTrustCheckAllowed(managedAgentEndpoint);
  const readOnlyProtocol = readOnlyTrustCheckProtocol(node, allNodes);
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
      {leg === 'transit-point' && isMigratedTrustCheck(config) && (
        <MigratedTrustCheckWarning
          testid="trust-check-panel-migrated-warning"
          onKeep={() => updateField('trust_check_migrated', false)}
        />
      )}
      {notSavedForTarget && (
        <div role="status" data-testid="trust-check-panel-managed-agent-target-warning">
          <InfoBanner
            title="This Trust Check blocks Save on a URL target"
            icon="fa-exclamation-triangle"
            variant="warning"
            collapsible={false}
            className="mt-2"
            summary={`The Managed Agent's own target-leg Trust Check runs only when it targets an A2A Proxy or another gateway. Remove it or switch the target. ${
              allNodes && managedAgentTrustCheckRunsOnTransitPoints(config, allNodes)
                ? MANAGED_AGENT_TRUST_CHECK_DUPLICATED_NOTE
                : "To check a Transit Point's target, drop a Trust Check on its arrow instead."
            }`}
          />
        </div>
      )}

      <div className="config-section">
        {leg === 'transit-point' && (
          <Form.Text
            className="text-muted d-block mb-1"
            style={{ fontSize: '11px' }}
            data-testid="trust-check-panel-transit-point-scope"
          >
            Applies to this Transit Point only.
          </Form.Text>
        )}
        {readOnlyProtocol && (
          <Form.Text
            className="d-block mb-1"
            style={{ fontSize: '11px' }}
            data-testid="trust-check-panel-read-only"
          >
            {readOnlyTrustCheckMessage(readOnlyProtocol)}
          </Form.Text>
        )}
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
          {readOnlyProtocol ? 'View Queries…' : 'Configure Queries…'}
        </AppButton>
      </div>
    </>
  );
};

export default TrustCheckPanel;
