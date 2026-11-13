import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import { getAuthorities } from '../../../../utils/authoritiesCache';
import { getIssuers } from '../../../../utils/issuersCache';
import { topAndTail } from '../../../../utils/stringUtils';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import type { ConfigPanelProps } from '../types';
import {
  authorityRows,
  isMigratedTrustCheck,
  makeDefaultQuery,
  queryAuthorityMissing,
  readOnlyTrustCheckMessage,
  readOnlyTrustCheckProtocol,
  readQueries,
  trustCheckLeg,
  type TrustCheckQueryConfig,
  type TrustCheckRecordType,
} from './definition';
import { describeTrustCheckLeg } from './legContext';
import TrustCheckQueryForm from './TrustCheckQueryForm';
import TrustCheckQueryList from './TrustCheckQueryList';
import MigratedTrustCheckWarning from './MigratedTrustCheckWarning';

/** A query added since the editor opened: every Authority it lists is new. */
const NO_BASELINE: ReadonlySet<string> = new Set();

function seedInitial(config: any): TrustCheckQueryConfig[] {
  const existing = readQueries(config);
  return existing.length > 0 ? existing : [makeDefaultQuery()];
}

/**
 * Fullscreen editor for the Trust Check element: one card that fills the
 * editor tab, with the query list in its own scrolling pane and the settings
 * of the query selected there in the other, so neither grows the page. Below
 * 720px wide the list sits above the settings. Changes stay in a draft until
 * Save, which validates every query before it writes.
 */
const TrustCheckFullscreenPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  updateFields,
  closeFullscreenEditor,
  allNodes,
}) => {
  const leg = trustCheckLeg(node, allNodes);
  const readOnlyProtocol = readOnlyTrustCheckProtocol(node, allNodes);
  const isApMa = leg === 'caller';
  const legLabel = isApMa ? 'caller' : 'target';
  const legContext = describeTrustCheckLeg(leg);

  const [registries, setRegistries] = useState<TrustRegistry[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [authoritiesLoaded, setAuthoritiesLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .listTrustRegistries()
      .then(list => {
        if (!cancelled) setRegistries(list);
      })
      .catch(err => {
        if (!cancelled) setLoadError(err?.message || 'Failed to load trust registries');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    getIssuers({ refresh: true })
      .then(data => {
        if (alive) setIssuers(data);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    getAuthorities({ refresh: true })
      .then(data => {
        if (!alive) return;
        setAuthorities(data);
        setAuthoritiesLoaded(true);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const initial = useMemo(() => seedInitial(config), [config]);
  const [draft, setDraft] = useState<TrustCheckQueryConfig[]>(initial);
  const initialJson = useMemo(() => JSON.stringify(initial), [initial]);
  const draftJson = useMemo(() => JSON.stringify(draft), [draft]);
  const hasChanges = draftJson !== initialJson;
  // The Authorities each query listed when the editor opened, so the ones added since show as New.
  const baselineById = useMemo(
    () =>
      new Map(initial.map(q => [q.id, new Set(authorityRows(q).map(r => r.did.trim()))] as const)),
    [initial]
  );

  const [requestedIdx, setRequestedIdx] = useState(0);
  const selectedIdx = Math.min(requestedIdx, Math.max(draft.length - 1, 0));
  const [saveAttempted, setSaveAttempted] = useState(false);

  const registryNameById = useMemo(
    () => new Map(registries.map(r => [r.id, r.name] as const)),
    [registries]
  );
  // Issuers win on a DID in both registers, as in the picker.
  const authorityNameByDid = useMemo(
    () => new Map([...authorities, ...issuers].map(entry => [entry.did, entry.name] as const)),
    [authorities, issuers]
  );

  const updateQueryAt = (idx: number, patch: Partial<TrustCheckQueryConfig>) => {
    setDraft(prev => prev.map((q, i) => (i === idx ? { ...q, ...patch } : q)));
  };

  const replaceQueryAt = (idx: number, next: TrustCheckQueryConfig) => {
    setDraft(prev => prev.map((q, i) => (i === idx ? next : q)));
  };

  const updateQuerySubField = (idx: number, field: string, value: string) => {
    setDraft(prev =>
      prev.map((q, i) => {
        if (i !== idx) return q;
        const cur = q.query || {};
        if (!value) {
          const { [field]: _drop, ...rest } = cur;
          void _drop;
          return { ...q, query: rest };
        }
        return { ...q, query: { ...cur, [field]: value } };
      })
    );
  };

  const updateEntityAt = (idx: number, value: string) => {
    updateQuerySubField(idx, 'entity_id', value);
  };

  const handleQueryTypeChangeAt = (idx: number, next: TrustCheckRecordType) => {
    setDraft(prev => prev.map((q, i) => (i === idx ? { ...q, query_type: next } : q)));
  };

  const addQuery = () => {
    setDraft([...draft, makeDefaultQuery()]);
    setRequestedIdx(draft.length);
  };

  // As in `CallerAuthMethodList`: removing the selected query selects the one before it.
  const removeQueryAt = (idx: number) => {
    setDraft(prev => prev.filter((_, i) => i !== idx));
    if (selectedIdx >= idx && selectedIdx > 0) setRequestedIdx(selectedIdx - 1);
  };

  const handleSave = () => {
    // Flip the save-attempted flag so per-field validation (e.g. Action /
    // Resource on an authorization query) surfaces its `isInvalid` state
    // and inline error message. If any authorization query is missing
    // Action or Resource, do not close — the operator sees the newly
    // revealed errors on the offending field(s) and can fix them.
    setSaveAttempted(true);
    const hasAuthorizationGap = (q: TrustCheckQueryConfig) => {
      const qt = q.query_type === 'recognition' ? 'recognition' : 'authorization';
      if (qt !== 'authorization') return false;
      const action = typeof q.query?.action === 'string' ? q.query.action.trim() : '';
      const resource = typeof q.query?.resource === 'string' ? q.query.resource.trim() : '';
      return !action || !resource;
    };
    // The Authority must be usable. On the target leg that means an
    // explicit Issuer / Authority literal DID (empty or a `{{ … }}`
    // template would trip the runtime trust-registry metadata gate). On
    // the caller leg a blank value is fine — it defaults to the verified
    // agent-identity-credential issuer — so only a *different* leftover
    // template blocks the save.
    const blocking = draft.findIndex(
      q => hasAuthorizationGap(q) || queryAuthorityMissing(q, isApMa)
    );
    if (blocking >= 0) {
      // Only the selected query's form shows its errors, so open the first one that blocks.
      setRequestedIdx(blocking);
      return;
    }
    updateFields({ queries: draft, trust_check_migrated: false });
    closeFullscreenEditor?.();
  };

  const handleDiscard = () => {
    closeFullscreenEditor?.();
  };

  const selected = draft[selectedIdx];

  return (
    <div className="card shadow-sm trust-check-editor">
      <div className="card-header d-flex align-items-center gap-2 py-2">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-certificate me-2" aria-hidden="true" />
          Trust Check
        </h6>
        <span
          className="badge rounded-pill text-bg-light border"
          data-testid="trust-check-fullscreen-leg-pill"
        >
          {isApMa ? 'Caller leg' : 'Target leg'}
        </span>
        {hasChanges && (
          <span className="ms-auto small text-warning" data-testid="trust-check-fullscreen-unsaved">
            <i className="fas fa-circle me-1" aria-hidden="true" />
            Unsaved changes
          </span>
        )}
      </div>

      <p
        className="small text-muted lh-base mb-0 px-4 py-3 border-bottom"
        data-testid="trust-check-fullscreen-leg"
      >
        {legContext.intro} Each query lands on OPA at{' '}
        <code>input.trust_check_results.{legLabel}[]</code> in the order shown; OPA decides allow or
        deny.
        {leg === 'transit-point' && <> Applies to this Transit Point only.</>}
      </p>
      {readOnlyProtocol && (
        <p className="small px-3 pt-2 mb-0" data-testid="trust-check-fullscreen-read-only">
          {readOnlyTrustCheckMessage(readOnlyProtocol)}
        </p>
      )}
      {leg === 'transit-point' && isMigratedTrustCheck(config) && (
        <div className="px-3">
          <MigratedTrustCheckWarning
            testid="trust-check-fullscreen-migrated-warning"
            onKeep={() => updateField('trust_check_migrated', false)}
          />
        </div>
      )}

      <div className="trust-check-editor-body">
        <div className="trust-check-editor-queries">
          <div className="px-3 py-2 border-bottom">
            <h2 className="h6 fw-bold m-0">Trust Check Queries</h2>
            <span className="d-block small text-muted" data-testid="trust-check-fullscreen-count">
              {draft.length} {draft.length === 1 ? 'query' : 'queries'}
            </span>
          </div>
          <div className="trust-check-editor-queries-list">
            {draft.length === 0 ? (
              <p className="text-muted small m-3" data-testid="trust-check-editor-empty-state">
                No queries yet. Add one to start checking the trust registry.
              </p>
            ) : (
              <TrustCheckQueryList
                queries={draft}
                isTargetLeg={!isApMa}
                area="trust-check-editor"
                registryName={id => registryNameById.get(id) ?? topAndTail(id, 8, 4)}
                authorityName={did => authorityNameByDid.get(did) ?? topAndTail(did, 16, 12)}
                selected={selectedIdx}
                onSelect={setRequestedIdx}
              />
            )}
          </div>
          <div className="px-3 border-top">
            <button
              type="button"
              className="btn btn-sm btn-link px-0"
              onClick={addQuery}
              disabled={!!readOnlyProtocol}
              data-testid="trust-check-add-query"
            >
              <i className="fas fa-plus me-1" aria-hidden="true" /> Add query
            </button>
          </div>
        </div>

        {selected && (
          <fieldset
            className="trust-check-editor-settings"
            disabled={!!readOnlyProtocol}
            data-testid="trust-check-editor-query-settings"
          >
            <div className="d-flex align-items-center gap-2 px-3 py-2 border-bottom">
              <h2 className="h6 fw-bold m-0 flex-grow-1">Query {selectedIdx + 1}</h2>
              <button
                type="button"
                className="btn btn-sm btn-outline-danger"
                onClick={() => removeQueryAt(selectedIdx)}
                data-testid="trust-check-editor-remove-query-button"
              >
                <i className="fas fa-trash me-1" aria-hidden="true" />
                Remove query
              </button>
            </div>
            <div className="trust-check-editor-settings-body">
              <TrustCheckQueryForm
                key={selected.id || `idx-${selectedIdx}`}
                queryConfig={selected}
                index={selectedIdx}
                isApMa={isApMa}
                registries={registries}
                issuers={issuers}
                authorities={authorities}
                authoritiesLoaded={authoritiesLoaded}
                loadError={loadError}
                updateQueryAt={updateQueryAt}
                updateQuerySubField={updateQuerySubField}
                replaceQueryAt={replaceQueryAt}
                baselineDids={baselineById.get(selected.id) ?? NO_BASELINE}
                updateEntityAt={updateEntityAt}
                handleQueryTypeChangeAt={handleQueryTypeChangeAt}
                saveAttempted={saveAttempted}
              />
            </div>
          </fieldset>
        )}
      </div>

      <div className="card-footer d-flex flex-wrap align-items-center justify-content-end gap-2">
        {!readOnlyProtocol && (
          <span className="small text-muted me-auto">
            Changes apply to the surface when you press Save.
          </span>
        )}
        <button
          type="button"
          className="btn btn-outline-secondary"
          onClick={handleDiscard}
          disabled={!closeFullscreenEditor}
          title={hasChanges ? 'Discard unsaved changes' : 'Close'}
          data-testid="trust-check-discard"
        >
          <i className="fas fa-times me-1" aria-hidden="true" />
          {hasChanges ? 'Discard' : 'Close'}
        </button>
        {!readOnlyProtocol && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleSave}
            disabled={!hasChanges || !closeFullscreenEditor}
            data-testid="trust-check-save"
          >
            <i className="fas fa-check me-1" aria-hidden="true" />
            Save
          </button>
        )}
      </div>
    </div>
  );
};

export default TrustCheckFullscreenPanel;
