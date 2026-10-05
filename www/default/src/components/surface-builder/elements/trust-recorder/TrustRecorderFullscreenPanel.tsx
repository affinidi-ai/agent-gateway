import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import { AppButton } from '../../../shared/AppButton';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import { getAuthorities } from '../../../../utils/authoritiesCache';
import type { ConfigPanelProps } from '../types';
import {
  makeDefaultCustomResource,
  makeDefaultEntry,
  readEntries,
  TRUST_RECORDER_ENTRIES_MAX,
  type CustomResource,
  type TrustRecorderEntry,
} from './definition';
import TrustRecorderEntryForm from './TrustRecorderEntryForm';

function seedInitial(config: any): TrustRecorderEntry[] {
  const existing = readEntries(config);
  return existing.length > 0 ? existing : [makeDefaultEntry()];
}

const TrustRecorderFullscreenPanel: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  closeFullscreenEditor,
}) => {
  const [registries, setRegistries] = useState<TrustRegistry[]>([]);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [issuersLoadError, setIssuersLoadError] = useState<string | null>(null);
  const [authoritiesLoadError, setAuthoritiesLoadError] = useState<string | null>(null);

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
    let cancelled = false;
    apiClient
      .listIssuers()
      .then(list => {
        if (!cancelled) setIssuers(list);
      })
      .catch(err => {
        if (!cancelled) setIssuersLoadError(err?.message || 'Failed to load issuers');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    getAuthorities({ refresh: true })
      .then(list => {
        if (!cancelled) setAuthorities(list);
      })
      .catch(err => {
        if (!cancelled) setAuthoritiesLoadError(err?.message || 'Failed to load authorities');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const initial = useMemo(() => seedInitial(config), [config]);
  const [draft, setDraft] = useState<TrustRecorderEntry[]>(initial);
  const initialJson = useMemo(() => JSON.stringify(initial), [initial]);
  const draftJson = useMemo(() => JSON.stringify(draft), [draft]);
  const hasChanges = draftJson !== initialJson;

  const [expandedIdx, setExpandedIdx] = useState<number | null>(() =>
    initial.length > 1 ? null : 0
  );
  const [saveAttempted, setSaveAttempted] = useState(false);

  const updateEntry = (idx: number, patch: Partial<TrustRecorderEntry>) => {
    setDraft(prev => prev.map((e, i) => (i === idx ? { ...e, ...patch } : e)));
  };

  const updateCustomResourceAt = (
    idx: number,
    resourceIdx: number,
    patch: Partial<CustomResource>
  ) => {
    setDraft(prev =>
      prev.map((e, i) => {
        if (i !== idx) return e;
        const next = e.custom_resources.map((r, ri) =>
          ri === resourceIdx ? { ...r, ...patch } : r
        );
        return { ...e, custom_resources: next };
      })
    );
  };

  const addCustomResource = (idx: number) => {
    setDraft(prev =>
      prev.map((e, i) =>
        i === idx
          ? { ...e, custom_resources: [...e.custom_resources, makeDefaultCustomResource()] }
          : e
      )
    );
  };

  const removeCustomResourceAt = (idx: number, resourceIdx: number) => {
    setDraft(prev =>
      prev.map((e, i) => {
        if (i !== idx) return e;
        return {
          ...e,
          custom_resources: e.custom_resources.filter((_, ri) => ri !== resourceIdx),
        };
      })
    );
  };

  const addEntry = () => {
    if (draft.length >= TRUST_RECORDER_ENTRIES_MAX) return;
    const next = [...draft, makeDefaultEntry()];
    setDraft(next);
    setExpandedIdx(next.length - 1);
  };

  const removeEntryAt = (idx: number) => {
    setDraft(prev => prev.filter((_, i) => i !== idx));
    if (expandedIdx === idx) setExpandedIdx(null);
    else if (expandedIdx !== null && expandedIdx > idx) setExpandedIdx(expandedIdx - 1);
  };

  const handleSave = () => {
    // Flip the save-attempted flag so per-field validation (missing
    // Trust Registry / Issuer / Authority, or no record source enabled)
    // surfaces its `isInvalid` state and inline error message on the
    // entry form. If any entry has a gap, do not close — the operator
    // sees the newly revealed errors and can fix them.
    setSaveAttempted(true);
    const hasIncompleteEntry = draft.some(e => {
      if (!e.trust_registry_id || !e.issuer_did || !e.authority_did) return true;
      const hasCompleteCustom = e.custom_resources.some(
        r =>
          r.action.trim().length > 0 &&
          r.resource.trim().length > 0 &&
          r.record_type.trim().length > 0
      );
      return !e.include_owned_agent && !hasCompleteCustom;
    });
    if (hasIncompleteEntry) return;
    // Strip incomplete custom resources (missing action, resource, or record_type) before persisting.
    const cleaned = draft.map(e => ({
      ...e,
      custom_resources: e.custom_resources.filter(
        r =>
          r.action.trim().length > 0 &&
          r.resource.trim().length > 0 &&
          r.record_type.trim().length > 0
      ),
    }));
    updateField('entries', cleaned);
    closeFullscreenEditor?.();
  };

  const handleDiscard = () => {
    closeFullscreenEditor?.();
  };

  const registryNameById = (id?: string): string => {
    if (!id) return 'no registry';
    return registries.find(r => r.id === id)?.name || id;
  };

  const renderCard = (entry: TrustRecorderEntry, idx: number) => {
    const expanded = expandedIdx === idx;
    const triples = entry.include_owned_agent ? 'ownedAgent' : '';
    const custom =
      entry.custom_resources.length > 0 ? ` · +${entry.custom_resources.length} custom` : '';
    const headerSummary = `${registryNameById(entry.trust_registry_id)}${triples ? ` · ${triples}` : ''}${custom}`;

    return (
      <div
        key={`entry-${idx}`}
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
          <strong style={{ fontSize: '13px' }}>Entry {idx + 1}</strong>
          <span className="text-muted" style={{ fontSize: '12px', flex: 1 }}>
            {headerSummary}
          </span>
          <button
            type="button"
            className="btn btn-outline-danger btn-sm"
            onClick={e => {
              e.stopPropagation();
              removeEntryAt(idx);
            }}
            title="Remove entry"
            style={{ padding: '2px 8px' }}
            data-testid={`trust-recorder-entry-${idx}-remove`}
          >
            <i className="fas fa-times" />
          </button>
        </div>

        {expanded && (
          <TrustRecorderEntryForm
            entry={entry}
            index={idx}
            registries={registries}
            issuers={issuers}
            authorities={authorities}
            loadError={loadError}
            issuersLoadError={issuersLoadError}
            authoritiesLoadError={authoritiesLoadError}
            updateEntry={updateEntry}
            updateCustomResourceAt={updateCustomResourceAt}
            addCustomResource={addCustomResource}
            removeCustomResourceAt={removeCustomResourceAt}
            saveAttempted={saveAttempted}
          />
        )}
      </div>
    );
  };

  const atCap = draft.length >= TRUST_RECORDER_ENTRIES_MAX;

  return (
    <div className="container-fluid py-4">
      <div className="mb-4">
        <h4 className="mb-1">
          <i className="fas fa-pen-to-square me-2" style={{ color: '#8e44ad' }} />
          Trust Recorder
        </h4>
        <div className="text-muted small">
          Writes agent-registration records on the <strong>response leg</strong> (Managed Agent
          &rarr; Access Point) to every configured Trust Registry.
        </div>
        <div className="text-muted small mt-1">
          <strong>
            Only a maximum of {TRUST_RECORDER_ENTRIES_MAX} records allowed per Trust Recorder.
          </strong>
        </div>
      </div>

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex align-items-center justify-content-between">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-list me-2" />
            Records
          </h6>
          <span className="badge text-bg-light border">
            {draft.length}/{TRUST_RECORDER_ENTRIES_MAX}
          </span>
        </div>
        <div className="card-body">
          {draft.length === 0 ? (
            <p className="text-muted small mb-3">
              No records yet. Add one to record agent registrations.
            </p>
          ) : (
            draft.map((entry, idx) => renderCard(entry, idx))
          )}

          <button
            type="button"
            className="btn btn-outline-primary btn-sm"
            onClick={addEntry}
            disabled={atCap}
            title={atCap ? `Maximum ${TRUST_RECORDER_ENTRIES_MAX} records` : undefined}
            data-testid="trust-recorder-add-entry"
          >
            <i className="fas fa-plus me-1" /> Add Record
          </button>
        </div>
      </div>

      <div className="d-flex justify-content-end gap-2">
        <AppButton
          variant="secondary"
          size="md"
          onClick={handleDiscard}
          disabled={!closeFullscreenEditor}
          title={hasChanges ? 'Discard unsaved changes' : 'Close'}
          iconStart={<i className="fas fa-times me-1" aria-hidden="true" />}
          data-testid="trust-recorder-discard"
        >
          {hasChanges ? 'Discard' : 'Close'}
        </AppButton>
        <AppButton
          variant="primary"
          size="md"
          onClick={handleSave}
          disabled={!hasChanges || !closeFullscreenEditor}
          iconStart={<i className="fas fa-check me-1" aria-hidden="true" />}
          data-testid="trust-recorder-save"
        >
          Save
        </AppButton>
      </div>
    </div>
  );
};

export default TrustRecorderFullscreenPanel;
