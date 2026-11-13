import React, { useEffect, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import type { Authority, Issuer } from '../../../../types';
import { topAndTail } from '../../../../utils/stringUtils';
import { deepLinks } from '../../../../utils/deepLinks';
import AddResourceLink from '../../../shared/AddResourceLink';
import MissingAuthorityWarning from '../_shared/MissingAuthorityWarning';
import { AGENT_IDENTITY_ISSUER_DID_TEMPLATE, INPUT_GATEWAY_SOURCE_ID_TEMPLATE } from './templates';
import {
  appendAuthorityRows,
  authorityNeedsSelection,
  authorityRows,
  classifyTargetAuthoritySelection,
  isMultiAuthorityQuery,
  removeAuthorityRow,
  type AuthorityRow,
  type TrustCheckQueryConfig,
} from './definition';

/** Rows past this many get a filter box above the table. */
const FILTER_FROM = 8;

/** The caller-leg values taken from each request rather than from a register. */
const REQUEST_OPTIONS = [
  {
    key: 'agent-identity-issuer',
    did: AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
    label: 'Agent identity credential issuer',
    detail:
      'The verified issuer of the caller’s agent identity credential. The caller-leg default.',
  },
  {
    key: 'sending-gateway',
    did: INPUT_GATEWAY_SOURCE_ID_TEMPLATE,
    label: 'Sending gateway DID (fabric-inbound)',
    detail:
      'The gateway that sent the request over fabric://. Empty on a direct request, so the result fails.',
  },
] as const;

interface AuthorityListEditorProps {
  /** `trust-check-query-<n>` */
  tidPrefix: string;
  isApMa: boolean;
  queryConfig: TrustCheckQueryConfig;
  issuers: Issuer[];
  authorities: Authority[];
  /** False while the Authorities register loads or after it failed: nothing is reported deleted. */
  authoritiesLoaded: boolean;
  saveAttempted: boolean;
  /** Values the query held when the editor opened; any other listed value is marked New. */
  baselineDids?: ReadonlySet<string>;
  onChange: (next: TrustCheckQueryConfig) => void;
}

interface RowView {
  key: string;
  did: string;
  name: string;
  kind: string;
  detail: string;
  /** The detail is a DID or template (shown as code) rather than a description. */
  detailIsDid: boolean;
  missing: boolean;
  invalid: boolean;
  isNew: boolean;
  removable: boolean;
}

interface Option {
  key: string;
  did: string;
  source?: 'issuer' | 'authority';
  label: string;
  detail: string;
}

function ordinal(n: number): string {
  const tens = n % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  return `${n}${['th', 'st', 'nd', 'rd'][n % 10] ?? 'th'}`;
}

function describeRow(row: AuthorityRow, index: number, props: AuthorityListEditorProps): RowView {
  const { isApMa, issuers, authorities, authoritiesLoaded, saveAttempted, baselineDids } = props;
  const did = row.did.trim();
  const base = {
    key: did || `empty-${index}`,
    did,
    missing: false,
    isNew: !!did && !!baselineDids && !baselineDids.has(did),
    removable: true,
    invalid: saveAttempted && (did === '' || authorityNeedsSelection(did, isApMa)),
  };
  if (did === '') {
    return {
      ...base,
      name: 'Select an Issuer or Authority',
      kind: 'Empty',
      detail: '',
      detailIsDid: false,
    };
  }
  const request = isApMa ? REQUEST_OPTIONS.find(o => o.did === did) : undefined;
  if (request) {
    return {
      ...base,
      name: request.label,
      kind: 'From request',
      detail: request.detail,
      detailIsDid: false,
    };
  }
  /** The register entry's description when it has one, else the shortened DID. */
  const described = (entries: ReadonlyArray<{ did: string; description?: string }>) => {
    const description = entries.find(e => e.did === did)?.description?.trim();
    return description
      ? { detail: description, detailIsDid: false }
      : { detail: topAndTail(did, 16, 12), detailIsDid: true };
  };
  const selection = classifyTargetAuthoritySelection(
    did,
    issuers,
    authorities,
    row.source,
    authoritiesLoaded
  );
  switch (selection.kind) {
    case 'issuer':
      return { ...base, name: selection.name, kind: 'Issuer', ...described(issuers) };
    case 'authority':
      return { ...base, name: selection.name, kind: 'Authority', ...described(authorities) };
    case 'missing-authority':
      return {
        ...base,
        name: 'Deleted Authority',
        kind: 'Authority',
        detail: topAndTail(did, 16, 12),
        detailIsDid: true,
        missing: true,
        invalid: true,
      };
    case 'legacy-template':
      return {
        ...base,
        name: 'Legacy template (from JSON API)',
        kind: 'Template',
        detail: did,
        detailIsDid: true,
      };
    default:
      return {
        ...base,
        name: 'Custom DID (from JSON API)',
        kind: 'DID',
        detail: topAndTail(did, 16, 12),
        detailIsDid: true,
      };
  }
}

/**
 * A query's Authorities: a multi-select dropdown that appends Issuers and Authorities (and, on
 * the caller leg, the two values taken from the request) in the order they are ticked, and a
 * compact table of the listed ones in result order. One row saves `authority_id`; two or more
 * save `authority_ids` with the register each was picked from. A caller-leg query with none uses
 * the agent identity credential issuer by default.
 */
const AuthorityListEditor: React.FC<AuthorityListEditorProps> = props => {
  const { tidPrefix, isApMa, queryConfig, issuers, authorities, saveAttempted, onChange } = props;
  const tid = (suffix: string) => `${tidPrefix}-${suffix}`;
  const rows = authorityRows(queryConfig);
  const isDefault = !isMultiAuthorityQuery(queryConfig) && rows[0]?.did.trim() === '';
  const views = isDefault ? [] : rows.map((row, i) => describeRow(row, i, props));
  const missing = views.flatMap((v, index) => (v.missing ? [{ index, did: v.did }] : []));
  const newCount = views.filter(v => v.isNew).length;

  const [filter, setFilter] = useState('');
  const [added, setAdded] = useState<string[]>([]);
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const removeRefs = useRef(new Map<string, HTMLButtonElement>());

  useEffect(() => {
    if (!focusKey) return;
    removeRefs.current.get(focusKey)?.focus();
    setFocusKey(null);
  }, [focusKey]);

  const change = (next: TrustCheckQueryConfig) => {
    setAdded([]);
    onChange(next);
  };

  // The filter box shows only past FILTER_FROM rows; below that a leftover filter is ignored, so
  // rows never stay hidden with no box to clear it.
  const filterShown = views.length > FILTER_FROM;
  const needle = filterShown ? filter.trim().toLowerCase() : '';
  const filtering = needle !== '';
  const shown = views
    .map((view, index) => ({ view, index }))
    .filter(
      ({ view }) =>
        !filtering ||
        view.name.toLowerCase().includes(needle) ||
        view.did.toLowerCase().includes(needle)
    );
  const noRegisters = !isApMa && issuers.length === 0 && authorities.length === 0;

  return (
    <div className="d-flex flex-column gap-2">
      <div className="d-flex flex-wrap align-items-baseline gap-2">
        <span className="form-label fw-bold mb-0">Authorities</span>
        <span className="small text-muted" data-testid={tid('authority-count')}>
          {isDefault
            ? isApMa
              ? 'Agent identity credential issuer (default)'
              : 'None yet'
            : `${views.length} ${views.length === 1 ? 'Authority' : 'Authorities'}`}
        </span>
      </div>

      {noRegisters ? (
        <Form.Text className="text-muted d-block" data-testid={tid('authority-locked')}>
          No Issuers or Authorities configured. Add an{' '}
          <AddResourceLink to={deepLinks.issuer} testid={tid('authority-add-issuer-link')}>
            Issuer
          </AddResourceLink>{' '}
          or an{' '}
          <AddResourceLink to={deepLinks.authority} testid={tid('authority-add-authority-link')}>
            Authority
          </AddResourceLink>{' '}
          to check the target against.
        </Form.Text>
      ) : (
        <AddAuthoritiesDropdown
          tidPrefix={tidPrefix}
          isApMa={isApMa}
          issuers={issuers}
          authorities={authorities}
          listed={views.map(v => v.did)}
          onAdd={(picks, names) => {
            onChange(appendAuthorityRows(queryConfig, picks));
            setAdded(names);
          }}
        />
      )}

      {added.length > 0 && (
        <div
          role="status"
          className="alert alert-success py-1 px-2 mb-0 small"
          data-testid={tid('authority-added')}
        >
          <i className="fas fa-check me-1" aria-hidden="true" />
          Added {added.length} at the end: {added.join(', ')}.
        </div>
      )}

      {isDefault ? (
        <div
          className={`trust-check-authority-empty border rounded px-2 py-2 small ${
            saveAttempted && !isApMa ? 'is-invalid border-danger text-danger' : 'text-muted'
          }`}
          data-testid={tid('authority-empty')}
        >
          {isApMa
            ? 'No Issuer or Authority listed, so the agent identity credential issuer is used. Add one to check against it instead.'
            : 'No Issuer or Authority yet. Add at least one to check the target against.'}
        </div>
      ) : (
        <div className="border rounded" data-testid={tid('authorities')}>
          {(filterShown || newCount > 0 || missing.length > 0) && (
            <div className="d-flex align-items-center gap-2 px-2 py-1 border-bottom bg-body-tertiary small">
              {filterShown ? (
                <input
                  type="search"
                  className="form-control form-control-sm border-0 bg-transparent flex-grow-1 trust-check-authority-search"
                  placeholder={`Filter ${views.length} Authorities`}
                  aria-label="Filter Authorities"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  data-testid={tid('authority-filter')}
                />
              ) : (
                <span className="flex-grow-1" />
              )}
              {newCount > 0 && <span className="text-success text-nowrap">{newCount} new</span>}
              {missing.length > 0 && (
                <span className="text-danger text-nowrap">{missing.length} deleted</span>
              )}
            </div>
          )}
          <ul className="list-unstyled mb-0 trust-check-authority-list">
            {shown.map(({ view, index }) => (
              <li
                key={view.key}
                className={`trust-check-authority-row d-flex align-items-center gap-2 px-2 py-1 border-bottom${
                  view.invalid ? ' is-invalid' : ''
                }${view.missing ? ' bg-danger-subtle' : view.isNew ? ' bg-success-subtle' : ''}`}
                data-testid={tid(`authority-${index}`)}
              >
                <span className="small text-muted text-end trust-check-authority-index">
                  {index + 1}
                </span>
                <span className="d-flex align-items-baseline gap-2 flex-grow-1 text-truncate">
                  <span
                    className={`small fw-semibold text-nowrap${view.missing || view.invalid ? ' text-danger' : ''}`}
                  >
                    {view.name}
                  </span>
                  {view.detailIsDid ? (
                    <code className="small text-muted text-truncate" title={view.did}>
                      {view.detail}
                    </code>
                  ) : (
                    <span className="small text-muted text-truncate" title={view.did}>
                      {view.detail}
                    </span>
                  )}
                </span>
                {view.isNew && <span className="badge text-bg-success">New</span>}
                <span className="badge text-bg-light border">{view.kind}</span>
                <button
                  type="button"
                  ref={el => {
                    if (el) removeRefs.current.set(view.key, el);
                    else removeRefs.current.delete(view.key);
                  }}
                  className="btn btn-sm btn-link text-danger px-1"
                  aria-label={`Remove ${view.name}`}
                  onClick={() => {
                    // Keep focus in the list: on the row that takes this one's place, else the one before.
                    const next = views[index + 1] ?? views[index - 1];
                    if (next) setFocusKey(next.key);
                    change(removeAuthorityRow(queryConfig, index));
                  }}
                  data-testid={tid(`authority-${index}-remove`)}
                >
                  <i className="fas fa-trash" aria-hidden="true" />
                </button>
              </li>
            ))}
            {views.length === 0 && (
              <li
                className={`trust-check-authority-row px-2 py-2 small ${
                  saveAttempted ? 'is-invalid text-danger' : 'text-muted'
                }`}
                data-testid={tid('authority-empty')}
              >
                No Issuer or Authority listed. Add at least one.
              </li>
            )}
            {views.length > 0 && shown.length === 0 && (
              <li className="px-2 py-2 small text-muted">No Authority matches the filter.</li>
            )}
          </ul>
        </div>
      )}

      <MissingAuthorityWarning
        testid={tid('authority-missing')}
        element="trust-check"
        missing={missing}
        itemLabel={views.length > 1 ? 'Row' : undefined}
      />
    </div>
  );
};

interface AddAuthoritiesDropdownProps {
  tidPrefix: string;
  isApMa: boolean;
  issuers: Issuer[];
  authorities: Authority[];
  /** Values the query already lists, in row order. */
  listed: readonly string[];
  onAdd: (picks: AuthorityRow[], names: string[]) => void;
}

/**
 * Multi-select dropdown of what can be added: on the caller leg the request values, then the
 * Authorities and the Issuers (a DID in both registers shows once, as an Issuer). It opens on
 * click or keyboard, with a search box; values the query lists show ticked and locked with their
 * row, and ticked ones are added in the order they were ticked.
 */
const AddAuthoritiesDropdown: React.FC<AddAuthoritiesDropdownProps> = ({
  tidPrefix,
  isApMa,
  issuers,
  authorities,
  listed,
  onAdd,
}) => {
  const tid = (suffix: string) => `${tidPrefix}-${suffix}`;
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [picks, setPicks] = useState<Option[]>([]);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const close = () => {
    setOpen(false);
    setSearch('');
    setPicks([]);
  };

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) close();
    };
    document.addEventListener('mousedown', onPointer);
    return () => document.removeEventListener('mousedown', onPointer);
  }, [open]);

  const issuerDids = new Set(issuers.map(i => i.did));
  const groups: Array<{ title: string; options: Option[] }> = [
    ...(isApMa
      ? [
          {
            title: 'From the request · caller leg',
            options: REQUEST_OPTIONS.map(o => ({ ...o })),
          },
        ]
      : []),
    {
      title: 'Authorities',
      options: authorities
        .filter(a => !issuerDids.has(a.did))
        .map(a => ({
          key: a.did,
          did: a.did,
          source: 'authority' as const,
          label: a.name,
          detail: a.description || topAndTail(a.did, 16, 12),
        })),
    },
    {
      title: 'Issuers',
      options: issuers.map(i => ({
        key: i.did,
        did: i.did,
        source: 'issuer' as const,
        label: i.name,
        detail: i.description || topAndTail(i.did, 16, 12),
      })),
    },
  ];
  const needle = search.trim().toLowerCase();
  const shown = groups
    .map(g => ({
      ...g,
      options: g.options.filter(
        o =>
          !needle || o.label.toLowerCase().includes(needle) || o.did.toLowerCase().includes(needle)
      ),
    }))
    .filter(g => g.options.length > 0);

  const toggle = (option: Option) =>
    setPicks(prev =>
      prev.some(p => p.did === option.did)
        ? prev.filter(p => p.did !== option.did)
        : [...prev, option]
    );

  const confirm = () => {
    if (picks.length === 0) return;
    onAdd(
      picks.map(p => ({ did: p.did, source: p.source })),
      picks.map(p => p.label)
    );
    close();
    triggerRef.current?.focus();
  };

  return (
    <div
      ref={rootRef}
      className="position-relative"
      onBlur={e => {
        // Tabbing out of the dropdown closes it, as a click outside does.
        // A click on blank space inside moves focus nowhere (null), so only an element outside counts.
        const to = e.relatedTarget as Node | null;
        if (open && to && !rootRef.current?.contains(to)) close();
      }}
      onKeyDown={e => {
        if (e.key === 'Escape' && open) {
          e.stopPropagation();
          close();
          triggerRef.current?.focus();
        }
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        className={`form-select form-select-sm text-start text-truncate${open ? ' border-primary' : ''}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => (open ? close() : setOpen(true))}
        data-testid={tid('add-authority')}
      >
        <i className="fas fa-plus text-primary me-2" aria-hidden="true" />
        Add Issuers or Authorities
      </button>
      {open && (
        <div
          className="dropdown-menu show w-100 p-0 shadow trust-check-authority-menu"
          role="dialog"
          aria-label="Add Issuers or Authorities"
          data-testid={tid('add-authority-menu')}
        >
          <div className="p-2 border-bottom">
            <input
              type="search"
              className="form-control form-control-sm trust-check-authority-search"
              placeholder="Search Issuers and Authorities"
              aria-label="Search Issuers and Authorities"
              value={search}
              onChange={e => setSearch(e.target.value)}
              autoFocus
              data-testid={tid('add-authority-search')}
            />
          </div>
          <div className="trust-check-authority-menu-options">
            {shown.length === 0 && (
              <div className="px-3 py-2 small text-muted">No Issuer or Authority matches.</div>
            )}
            {shown.map(group => (
              <div key={group.title} role="group" aria-label={group.title}>
                <div className="dropdown-header text-uppercase small fw-bold">{group.title}</div>
                {group.options.map(option => {
                  const inList = listed.includes(option.did);
                  const pickedAt = picks.findIndex(p => p.did === option.did);
                  const note = pickedAt >= 0 ? `New · ${ordinal(pickedAt + 1)}` : '';
                  return (
                    <label
                      key={option.key}
                      className={`dropdown-item d-flex align-items-center gap-2${
                        pickedAt >= 0 ? ' bg-primary-subtle' : ''
                      }`}
                    >
                      <input
                        type="checkbox"
                        className="form-check-input flex-shrink-0 m-0 trust-check-authority-option-check"
                        checked={inList || pickedAt >= 0}
                        disabled={inList}
                        onChange={() => toggle(option)}
                        data-testid={tid(`add-authority-option-${option.key}`)}
                      />
                      <span className="d-flex flex-column flex-grow-1 text-truncate">
                        <span className="fw-semibold text-truncate">{option.label}</span>
                        <span className="text-muted text-truncate trust-check-authority-option-detail">
                          {option.detail}
                        </span>
                      </span>
                      {note && <span className="small text-muted text-nowrap">{note}</span>}
                    </label>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="d-flex align-items-center gap-2 px-3 py-2 border-top bg-body-tertiary">
            <span className="small text-muted flex-grow-1">
              {picks.length === 0
                ? 'Tick the ones to add'
                : `${picks.length} selected · added in the order ticked`}
            </span>
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={() => {
                close();
                triggerRef.current?.focus();
              }}
              data-testid={tid('add-authority-cancel')}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={picks.length === 0}
              onClick={confirm}
              data-testid={tid('add-authority-confirm')}
            >
              Add{picks.length > 0 ? ` ${picks.length}` : ''}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default AuthorityListEditor;
