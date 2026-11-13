import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import type { TrustRegistry } from '../../../../types';
import { getAuthorities } from '../../../../utils/authoritiesCache';
import { getIssuers } from '../../../../utils/issuersCache';
import { topAndTail } from '../../../../utils/stringUtils';
import { managedAgentTargetLegTrustCheckAllowed } from '../edges/archetypes';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import MissingAuthorityWarning from '../_shared/MissingAuthorityWarning';
import MigratedTrustCheckWarning from './MigratedTrustCheckWarning';
import TrustCheckQueryList from './TrustCheckQueryList';
import { describeTrustCheckLeg } from './legContext';
import {
  MANAGED_AGENT_TRUST_CHECK_DUPLICATED_NOTE,
  managedAgentTrustCheckRunsOnTransitPoints,
  readOnlyTrustCheckMessage,
  readOnlyTrustCheckProtocol,
  isManagedAgentTrustCheck,
  isMigratedTrustCheck,
  missingTrustCheckAuthorities,
  readQueries,
  trustCheckLeg,
} from './definition';

const PREVIEW_MAX = 5;

/**
 * Compact sidebar panel for the Trust Check element: one row per query with
 * its status, type, registry and Authorities, and a link to the fullscreen
 * editor, laid out like the Caller Context panel.
 */
const TrustCheckPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  allNodes,
  updateField,
  openFullscreenEditor,
}) => {
  const leg = trustCheckLeg(node, allNodes);
  const legLabel = leg === 'caller' ? 'caller' : 'target';
  const legContext = describeTrustCheckLeg(leg);
  const managedAgentEndpoint = allNodes?.find(n => n.type === 'target')?.config?.endpoint;
  const notSavedForTarget =
    allNodes !== undefined &&
    isManagedAgentTrustCheck(node, allNodes) &&
    !managedAgentTargetLegTrustCheckAllowed(managedAgentEndpoint);
  const readOnlyProtocol = readOnlyTrustCheckProtocol(node, allNodes);
  const queries = readQueries(config);
  const authorityDids = useOptionalSurfaceMeta()?.authorityDids;
  const missingAuthorities = missingTrustCheckAuthorities(config, authorityDids);
  const hasQueries = queries.length > 0;
  const [registryNameById, setRegistryNameById] = useState<ReadonlyMap<string, string>>(
    () => new Map()
  );
  const [authorityNameByDid, setAuthorityNameByDid] = useState<ReadonlyMap<string, string>>(
    () => new Map()
  );
  useEffect(() => {
    if (!hasQueries) return undefined;
    let alive = true;
    // Best effort: without a register the rows show shortened ids instead of names.
    Promise.all([
      apiClient.listTrustRegistries().catch((): TrustRegistry[] => []),
      getIssuers().catch(() => []),
      getAuthorities().catch(() => []),
    ]).then(([registries, issuers, authorities]) => {
      if (!alive) return;
      setRegistryNameById(new Map(registries.map(r => [r.id, r.name] as const)));
      // Issuers win on a DID in both registers, as in the picker.
      setAuthorityNameByDid(
        new Map([...authorities, ...issuers].map(entry => [entry.did, entry.name] as const))
      );
    });
    return () => {
      alive = false;
    };
  }, [hasQueries]);

  return (
    <>
      {leg === 'transit-point' && isMigratedTrustCheck(config) && (
        <MigratedTrustCheckWarning
          testid="trust-check-panel-migrated-warning"
          onKeep={() => updateField('trust_check_migrated', false)}
        />
      )}
      <MissingAuthorityWarning
        testid="trust-check-panel-authority-missing"
        element="trust-check"
        missing={missingAuthorities}
        itemLabel={queries.length > 1 ? 'Query' : undefined}
      />
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

      <Form.Text className="text-muted d-block mb-1" data-testid="trust-check-panel-results-ref">
        {legContext.intro} Results land on OPA at{' '}
        <code>input.trust_check_results.{legLabel}[]</code>; OPA decides allow or deny.
        {leg === 'transit-point' && (
          <span data-testid="trust-check-panel-transit-point-scope">
            {' '}
            Applies to this Transit Point only.
          </span>
        )}
      </Form.Text>
      {readOnlyProtocol && (
        <Form.Text className="d-block mb-1" data-testid="trust-check-panel-read-only">
          {readOnlyTrustCheckMessage(readOnlyProtocol)}
        </Form.Text>
      )}

      <InfoBanner
        title="How does OPA use the result?"
        icon="fa-circle-info"
        testIdPrefix="trust-check-panel"
        summary={legContext.summary}
      />

      <div className="config-section">
        <label>Trust Check Queries</label>
        {hasQueries ? (
          <TrustCheckQueryList
            queries={queries}
            isTargetLeg={leg !== 'caller'}
            area="trust-check-panel"
            limit={PREVIEW_MAX}
            registryName={id => registryNameById.get(id) ?? topAndTail(id, 8, 4)}
            authorityName={did => authorityNameByDid.get(did) ?? topAndTail(did, 16, 12)}
          />
        ) : (
          <div
            className="border rounded text-center py-3 px-2 mb-2"
            data-testid="trust-check-panel-empty-state"
          >
            <div className="fw-bold small mb-1">
              <i className="fas fa-certificate me-2 text-muted" aria-hidden="true" />
              No trust checks yet
            </div>
            <Form.Text className="d-block text-muted">
              Add a query to have OPA verify {legContext.subject} against a trust registry.
            </Form.Text>
          </div>
        )}
        <button
          type="button"
          className="btn btn-sm btn-link px-0"
          onClick={() => openFullscreenEditor?.()}
          disabled={!openFullscreenEditor}
          data-testid="trust-check-panel-configure"
        >
          <i className={`fas ${readOnlyProtocol ? 'fa-eye' : 'fa-pen-to-square'} me-1`} />{' '}
          {readOnlyProtocol ? 'View queries' : 'Configure queries'}
        </button>
        <Form.Text className="text-muted d-block mt-1">
          Every query runs; OPA sees one result per query and per listed Authority.
        </Form.Text>
      </div>
    </>
  );
};

export default TrustCheckPanel;
