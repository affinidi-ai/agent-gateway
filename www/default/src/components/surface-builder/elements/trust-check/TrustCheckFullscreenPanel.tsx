import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import { getAuthorities } from '../../../../utils/authoritiesCache';
import { getIssuers } from '../../../../utils/issuersCache';
import { findSlotById } from '../edges/archetypes';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import type { ConfigPanelProps } from '../types';
import {
  authorityNeedsSelection,
  makeDefaultQuery,
  readQueries,
  type TrustCheckQueryConfig,
  type TrustCheckRecordType,
} from './definition';
import TrustCheckQueryForm from './TrustCheckQueryForm';

// Mirrors backend `TRUST_CHECK_LIST_MAX` in `src/config/agent_surface.rs`.
const TRUST_CHECK_LIST_MAX = 10;

function seedInitial(config: any): TrustCheckQueryConfig[] {
  const existing = readQueries(config);
  return existing.length > 0 ? existing : [makeDefaultQuery()];
}

const TrustCheckFullscreenPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const slotId = node.slotId || '';
  const resolved = slotId ? findSlotById(slotId) : undefined;
  const isApMa = resolved?.archetype.id === 'ap-ma' || config._edge === 'ap-ma';
  const legLabel = isApMa ? 'caller' : 'target';

  const [registries, setRegistries] = useState<TrustRegistry[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [authorities, setAuthorities] = useState<Authority[]>([]);

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
        if (alive) setAuthorities(data);
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

  const [expandedIdx, setExpandedIdx] = useState<number | null>(() =>
    initial.length > 1 ? null : 0
  );
  const [saveAttempted, setSaveAttempted] = useState(false);

  const updateQueryAt = (idx: number, patch: Partial<TrustCheckQueryConfig>) => {
    setDraft(prev => prev.map((q, i) => (i === idx ? { ...q, ...patch } : q)));
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

  const updateAuthorityAt = (idx: number, value: string) => {
    updateQuerySubField(idx, 'authority_id', value);
  };

  const updateEntityAt = (idx: number, value: string) => {
    updateQuerySubField(idx, 'entity_id', value);
  };

  const handleQueryTypeChangeAt = (idx: number, next: TrustCheckRecordType) => {
    setDraft(prev => prev.map((q, i) => (i === idx ? { ...q, query_type: next } : q)));
  };

  const addQuery = () => {
    if (draft.length >= TRUST_CHECK_LIST_MAX) return;
    const next = [...draft, makeDefaultQuery()];
    setDraft(next);
    setExpandedIdx(next.length - 1);
  };

  const removeQueryAt = (idx: number) => {
    setDraft(prev => prev.filter((_, i) => i !== idx));
    if (expandedIdx === idx) setExpandedIdx(null);
    else if (expandedIdx !== null && expandedIdx > idx) setExpandedIdx(expandedIdx - 1);
  };

  const handleSave = () => {
    // Flip the save-attempted flag so per-field validation (e.g. Action /
    // Resource on an authorization query) surfaces its `isInvalid` state
    // and inline error message. If any authorization query is missing
    // Action or Resource, do not close — the operator sees the newly
    // revealed errors on the offending field(s) and can fix them.
    setSaveAttempted(true);
    const hasAuthorizationGap = draft.some(q => {
      const qt = q.query_type === 'recognition' ? 'recognition' : 'authorization';
      if (qt !== 'authorization') return false;
      const action = typeof q.query?.action === 'string' ? q.query.action.trim() : '';
      const resource = typeof q.query?.resource === 'string' ? q.query.resource.trim() : '';
      return !action || !resource;
    });
    if (hasAuthorizationGap) return;
    // The Authority must be usable. On the target leg that means an
    // explicit Issuer / Authority literal DID (empty or a `{{ … }}`
    // template would trip the runtime trust-registry metadata gate). On
    // the caller leg a blank value is fine — it defaults to the verified
    // agent-identity-credential issuer — so only a *different* leftover
    // template blocks the save.
    const hasAuthorityGap = draft.some(q =>
      authorityNeedsSelection(q.query?.authority_id as string | undefined, isApMa)
    );
    if (hasAuthorityGap) return;
    updateField('queries', draft);
    closeFullscreenEditor?.();
  };

  const handleDiscard = () => {
    closeFullscreenEditor?.();
  };

  const registryNameById = (id?: string): string => {
    if (!id) return 'no registry';
    return registries.find(r => r.id === id)?.name || id;
  };

  const renderCard = (q: TrustCheckQueryConfig, idx: number) => {
    const queryType: TrustCheckRecordType =
      q.query_type === 'recognition' ? 'recognition' : 'authorization';
    const expanded = expandedIdx === idx;
    const nameValue = typeof q.name === 'string' ? q.name : '';
    const headerLabel = nameValue ? `Query ${idx + 1} · ${nameValue}` : `Query ${idx + 1}`;
    const headerSummary = `${queryType} · ${registryNameById(q.trust_registry_id)}`;

    return (
      <div
        key={q.id || `idx-${idx}`}
        className="mb-3"
        style={{ border: '1px solid #e9ecef', borderRadius: '6px', overflow: 'hidden' }}
      >
        <div
          className="d-flex align-items-center gap-2 p-2 entry-card-header"
          onClick={() => setExpandedIdx(expanded ? null : idx)}
        >
          <i
            className={`fas ${expanded ? 'fa-chevron-down' : 'fa-chevron-right'}`}
            style={{ fontSize: '10px', color: '#6c757d', width: '10px' }}
          />
          <strong style={{ fontSize: '13px' }}>{headerLabel}</strong>
          <span className="text-muted" style={{ fontSize: '12px', flex: 1 }}>
            {headerSummary}
          </span>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm"
            onClick={e => {
              e.stopPropagation();
              removeQueryAt(idx);
            }}
            title="Remove query"
            style={{ padding: '2px 8px' }}
            data-testid={`trust-check-query-${idx}-remove`}
          >
            <i className="fas fa-times" />
          </button>
        </div>

        {expanded && (
          <TrustCheckQueryForm
            queryConfig={q}
            index={idx}
            isApMa={isApMa}
            registries={registries}
            issuers={issuers}
            authorities={authorities}
            loadError={loadError}
            updateQueryAt={updateQueryAt}
            updateQuerySubField={updateQuerySubField}
            updateAuthorityAt={updateAuthorityAt}
            updateEntityAt={updateEntityAt}
            handleQueryTypeChangeAt={handleQueryTypeChangeAt}
            saveAttempted={saveAttempted}
          />
        )}
      </div>
    );
  };

  const atCap = draft.length >= TRUST_CHECK_LIST_MAX;

  return (
    <div className="container-fluid py-4">
      <div className="mb-4">
        <h4 className="mb-1">
          <i className="fas fa-certificate me-2" style={{ color: '#8e44ad' }} />
          Trust Check
        </h4>
        <div className="text-muted small">
          Runs on the <strong>{legLabel} leg</strong>. Each query lands on OPA at{' '}
          <code>input.trust_check_results.{legLabel}[]</code> in the order shown below.
        </div>
        <div className="text-muted small mt-1">
          <strong>Only a maximum of {TRUST_CHECK_LIST_MAX} queries allowed per Trust Check.</strong>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex align-items-center justify-content-between">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-list-check me-2" />
            Queries
          </h6>
          <span className="badge text-bg-light border">
            {draft.length}/{TRUST_CHECK_LIST_MAX}
          </span>
        </div>
        <div className="card-body">
          {draft.length === 0 ? (
            <p className="text-muted small mb-3">
              No queries yet. Add one to start checking the trust registry.
            </p>
          ) : (
            draft.map((q, idx) => renderCard(q, idx))
          )}

          <button
            type="button"
            className="btn btn-outline-primary btn-sm"
            onClick={addQuery}
            disabled={atCap}
            title={atCap ? `Maximum ${TRUST_CHECK_LIST_MAX} queries per leg` : undefined}
            data-testid="trust-check-add-query"
          >
            <i className="fas fa-plus me-1" /> Add Another Query
          </button>
        </div>
      </div>

      <div className="d-flex justify-content-end gap-2">
        <button
          type="button"
          className="btn btn-outline-secondary"
          onClick={handleDiscard}
          disabled={!closeFullscreenEditor}
          title={hasChanges ? 'Discard unsaved changes' : 'Close'}
          data-testid="trust-check-discard"
        >
          <i className="fas fa-times me-1" />
          {hasChanges ? 'Discard' : 'Close'}
        </button>
        <button
          type="button"
          className="btn btn-primary"
          onClick={handleSave}
          disabled={!hasChanges || !closeFullscreenEditor}
          data-testid="trust-check-save"
        >
          <i className="fas fa-check me-1" />
          Save
        </button>
      </div>
    </div>
  );
};

export default TrustCheckFullscreenPanel;
