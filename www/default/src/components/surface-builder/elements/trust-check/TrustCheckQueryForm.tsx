import React from 'react';
import { Form } from 'react-bootstrap';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import { topAndTail } from '../../../../utils/stringUtils';
import { deepLinks } from '../../../../utils/deepLinks';
import AddResourceLink from '../../../shared/AddResourceLink';
import FormSelect, { type FormSelectOption } from '../../../shared/FormSelect';
import FormMultiSelect from '../../../shared/FormMultiSelect';
import MissingAuthorityWarning from '../_shared/MissingAuthorityWarning';
import { AGENT_IDENTITY_ISSUER_DID_TEMPLATE, INPUT_GATEWAY_SOURCE_ID_TEMPLATE } from './templates';
import {
  authorityRows,
  classifyTargetAuthoritySelection,
  queryAuthorityMissing,
  readSubjectPickerState,
  subjectDescription,
  subjectForTemplate,
  subjectLabel,
  templateForSubject,
  type AuthorityRow,
  type NamedSubject,
  type SubjectPickerState,
  type TrustCheckQueryConfig,
  type TrustCheckRecordType,
} from './definition';

const QUERY_TYPES: ReadonlyArray<FormSelectOption<TrustCheckRecordType>> = [
  {
    value: 'authorization',
    label: 'Authorization',
    description: 'Query an authorization record from the Trust Registry',
  },
  {
    value: 'recognition',
    label: 'Recognition',
    description: 'Query a recognition record from the Trust Registry',
  },
];

// Named subjects surfaced by the Entity ID dropdown on the CALLER leg.
// `authority-did` and `provider` are intentionally omitted. Asking a
// trust registry "is the higher Authority DID the entity of this
// query?" is not a meaningful shape on either leg; and the Provider DID
// resolves via `{{ input.agent.provider_did }}`, a value derived from
// the caller's request-payload trust-registry metadata extension that
// trips the runtime TRUST_REGISTRY_METADATA_UNAVAILABLE gate whenever
// that extension is absent (e.g. a payload carrying only an identity
// credential). A legacy config that stored either subject here surfaces
// via the locked "Custom (from JSON API)" slot so the value is visible
// but not directly re-selectable.
//
// `identity-issuer` (`{{ input.agent.identity_issuer_did }}`) surfaces
// the cryptographically-verified issuer DID of the caller's
// `agent-identity-credential/v1` VP — the root-of-trust anchor that
// pairs with the caller-leg Authority default. Only meaningful as an
// Entity ID on the caller leg (target-side VPs are not verified per-leg).
const CALLER_ENTITY_SUBJECT_ORDER: readonly NamedSubject[] = [
  'agent-did',
  'extension-identity',
  'identity-issuer',
];

// Named subjects surfaced by the Entity ID dropdown on the TARGET leg.
// Only the target's agent DID is offered: the extension identity is a
// caller-side gateway-derived DID (not a meaningful target-entity
// probe), and the provider DID resolves via `{{ input.agent.provider_did
// }}` — a value that comes from the target's own trust-registry
// extension metadata and trips the runtime TRUST_REGISTRY_METADATA_UNAVAILABLE
// gate when the card omits it. A legacy config that stored either
// subject here surfaces via the locked "Custom (from JSON API)" slot.
const TARGET_ENTITY_SUBJECT_ORDER: readonly NamedSubject[] = ['agent-did'];

// Disabled `<option>` sentinels used as group headers in the target-leg
// Authority picker. `FormSelect` skips disabled options in keyboard nav
// and never commits them (the native `<button disabled>` blocks the
// click), so they read as non-selectable section labels.
const GRP_ISSUERS = '__grp_issuers__';
const GRP_AUTHORITIES = '__grp_authorities__';

const CALLER_TEMPLATES: ReadonlySet<string> = new Set([
  AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
  INPUT_GATEWAY_SOURCE_ID_TEMPLATE,
]);

// Sentinel value for the inline "Custom (from JSON API)" `<option>` that
// surfaces a stored value that isn't one of the four named subjects.
// Picking it is a no-op (the option preserves the current stored value);
// picking a named subject overwrites it.
const OPT_CUSTOM = '__custom__';

interface TrustCheckQueryFormProps {
  queryConfig: TrustCheckQueryConfig;
  index: number;
  isApMa: boolean;
  registries: TrustRegistry[];
  issuers: Issuer[];
  authorities: Authority[];
  /**
   * True once the Authorities register has loaded, so an Authority it no longer has can be
   * reported as deleted. Never set while it loads or after it failed to load.
   */
  authoritiesLoaded?: boolean;
  loadError: string | null;
  updateQueryAt: (index: number, patch: Partial<TrustCheckQueryConfig>) => void;
  updateQuerySubField: (index: number, field: string, value: string) => void;
  /** Set the query's Authorities to the multi-select's picks, in order. */
  setAuthoritiesAt: (index: number, picks: AuthorityRow[]) => void;
  updateEntityAt: (index: number, value: string) => void;
  handleQueryTypeChangeAt: (index: number, next: TrustCheckRecordType) => void;
  /**
   * When `true`, per-field validation errors (e.g. authorization Action /
   * Resource) surface their `isInvalid` state and inline feedback. Set by
   * the fullscreen panel on the first Save click so the operator doesn't
   * see red errors before they've tried to save.
   */
  saveAttempted?: boolean;
}

const TrustCheckQueryForm: React.FC<TrustCheckQueryFormProps> = ({
  queryConfig,
  index,
  isApMa,
  registries,
  issuers,
  authorities,
  authoritiesLoaded = true,
  loadError,
  updateQueryAt,
  updateQuerySubField,
  setAuthoritiesAt,
  updateEntityAt,
  handleQueryTypeChangeAt,
  saveAttempted = false,
}) => {
  const queryType: TrustCheckRecordType =
    queryConfig.query_type === 'recognition' ? 'recognition' : 'authorization';
  const sq = queryConfig.query || {};
  const entityValue: string = typeof sq.entity_id === 'string' ? sq.entity_id : '';
  const tid = (suffix: string) => `trust-check-query-${index}-${suffix}`;

  return (
    <div className="p-3" data-testid={tid('form')}>
      <div className="row g-3">
        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Trust Registry</Form.Label>
          <FormSelect<string>
            value={queryConfig.trust_registry_id || ''}
            options={registries.map(r => {
              const detail = r.description || (r.main_did ? topAndTail(r.main_did, 16, 12) : '');
              const description =
                r.connection_status !== 'connected'
                  ? detail
                    ? `Not connected (${r.connection_status}) · ${detail}`
                    : `Not connected (${r.connection_status})`
                  : detail || undefined;
              return {
                value: r.id,
                label: r.name,
                description,
              };
            })}
            onChange={next => updateQueryAt(index, { trust_registry_id: next })}
            placeholder="Select a trust registry"
            testid={tid('registry')}
          />
          {loadError && (
            <Form.Text className="text-danger" style={{ fontSize: '10px' }}>
              {loadError}
            </Form.Text>
          )}
          {!loadError && (
            <Form.Text className="text-muted d-block" style={{ fontSize: '11px' }}>
              {registries.length === 0
                ? 'No trust registries configured yet. '
                : "Don't see the one you need? "}
              <AddResourceLink to={deepLinks.trustRegistry} testid={tid('add-registry-link')}>
                Add Trust Registry
              </AddResourceLink>
            </Form.Text>
          )}
        </div>

        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Record Type</Form.Label>
          <FormSelect<TrustCheckRecordType>
            value={queryType}
            options={QUERY_TYPES}
            onChange={next => handleQueryTypeChangeAt(index, next)}
            testid={tid('type')}
          />
        </div>

        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Authority ID</Form.Label>
          <IssuerAuthorityPicker
            testid={tid('authority')}
            isApMa={isApMa}
            queryConfig={queryConfig}
            issuers={issuers}
            authorities={authorities}
            authoritiesLoaded={authoritiesLoaded}
            saveAttempted={saveAttempted}
            onChange={picks => setAuthoritiesAt(index, picks)}
          />
        </div>

        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Entity ID</Form.Label>
          <SubjectPickerSelect
            testid={tid('entity')}
            storedValue={entityValue}
            subjectOrder={isApMa ? CALLER_ENTITY_SUBJECT_ORDER : TARGET_ENTITY_SUBJECT_ORDER}
            isApMa={isApMa}
            onChange={wire => updateEntityAt(index, wire)}
          />
        </div>

        {queryType === 'authorization' ? (
          <>
            <div className="col-12">
              <Form.Label className="fw-semibold small mb-1">
                Action <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="text"
                required
                value={sq.action || ''}
                placeholder="e.g. issue"
                onChange={e => updateQuerySubField(index, 'action', e.target.value)}
                isInvalid={saveAttempted && !sq.action}
                data-testid={tid('action')}
              />
              <Form.Control.Feedback type="invalid">
                Action is required for authorization queries.
              </Form.Control.Feedback>
            </div>

            <div className="col-12">
              <Form.Label className="fw-semibold small mb-1">
                Resource <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="text"
                required
                value={sq.resource || ''}
                placeholder="e.g. credential:PaymentCredential"
                onChange={e => updateQuerySubField(index, 'resource', e.target.value)}
                isInvalid={saveAttempted && !sq.resource}
                data-testid={tid('resource')}
              />
              <Form.Control.Feedback type="invalid">
                Resource is required for authorization queries.
              </Form.Control.Feedback>
            </div>
          </>
        ) : (
          <>
            <div className="col-12">
              <Form.Label className="fw-semibold small mb-1">Action (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                value={sq.action || ''}
                placeholder="is (default)"
                onChange={e => updateQuerySubField(index, 'action', e.target.value)}
                data-testid={tid('action')}
              />
            </div>

            <div className="col-12">
              <Form.Label className="fw-semibold small mb-1">Resource (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                value={sq.resource || ''}
                placeholder="ownedAgent (default)"
                onChange={e => updateQuerySubField(index, 'resource', e.target.value)}
                data-testid={tid('resource')}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

/** Convert a `SubjectPickerState` into the `<select>`'s current value. */
function subjectPickerSelectValue(state: SubjectPickerState): string {
  return state.kind === 'subject' ? state.subject : OPT_CUSTOM;
}

interface SubjectPickerSelectProps {
  testid: string;
  storedValue: string;
  subjectOrder: readonly NamedSubject[];
  isApMa: boolean;
  onChange: (wireValue: string) => void;
}

/**
 * Subject-picker dropdown shared by Entity ID and the target-leg
 * Authority. Renders one FormSelect option per named subject (index 0
 * marked as default) with the short subject label as the header and a
 * plain-English explanation as the subheader. When the stored value is
 * not one of the named subjects, an additional disabled option
 * surfaces the JSON-API-authored custom value (the raw template / DID
 * as the subheader) so the operator can see what's stored but cannot
 * re-select it; picking a named subject overwrites it. The selected
 * option's description also renders on the FormSelect toggle, so no
 * separate below-field caption is required.
 */
const SubjectPickerSelect: React.FC<SubjectPickerSelectProps> = ({
  testid,
  storedValue,
  subjectOrder,
  isApMa,
  onChange,
}) => {
  // A stored value that resolves to a named subject the current
  // `subjectOrder` doesn't offer (e.g. legacy `authority-did` on the
  // Entity ID picker) is coerced into the custom slot so the operator
  // still sees the raw stored value in a locked option instead of a
  // blank toggle.
  const rawState = readSubjectPickerState(storedValue);
  const state: SubjectPickerState =
    rawState.kind === 'subject' && !subjectOrder.includes(rawState.subject)
      ? { kind: 'custom', value: storedValue }
      : rawState;
  const value = subjectPickerSelectValue(state);
  const options: Array<FormSelectOption<string>> = subjectOrder.map((subject, i) => ({
    value: subject,
    label: `${capitalize(subjectLabel(subject, isApMa))}${i === 0 ? ' (default)' : ''}`,
    description: subjectDescription(subject, isApMa),
  }));
  if (state.kind === 'custom') {
    const isDid = !state.value.includes('{{');
    options.push({
      value: OPT_CUSTOM,
      label: customOptionLabel(state.value, isApMa),
      description: isDid ? topAndTail(state.value, 16, 12) : state.value,
      disabled: true,
    });
  }
  const handleChange = (next: string) => {
    if (next === OPT_CUSTOM) return;
    onChange(templateForSubject(next as NamedSubject));
  };
  return (
    <FormSelect<string> value={value} options={options} onChange={handleChange} testid={testid} />
  );
};

/**
 * Label the inline "Custom (from JSON API)" `<option>` — a template that
 * happens to resolve via the shared vocabulary map gets its plain-English
 * label, otherwise falls back to a generic Custom label.
 */
function customOptionLabel(value: string, isApMa: boolean): string {
  const label = subjectLabelFromTemplate(value, isApMa);
  return label ? `${capitalize(label)} (from JSON API)` : 'Custom (from JSON API)';
}

/**
 * Reverse-lookup a stored template string to a plain-English subject
 * label via the shared vocabulary map. Returns `null` when the template
 * isn't one of the four named subjects.
 */
function subjectLabelFromTemplate(template: string, isApMa: boolean): string | null {
  const subject = subjectForTemplate(template);
  return subject ? subjectLabel(subject, isApMa) : null;
}

function capitalize(s: string): string {
  return s.length === 0 ? s : s[0].toUpperCase() + s.slice(1);
}

interface IssuerAuthorityPickerProps {
  /** `trust-check-query-<n>-authority` */
  testid: string;
  isApMa: boolean;
  queryConfig: TrustCheckQueryConfig;
  issuers: Issuer[];
  authorities: Authority[];
  authoritiesLoaded: boolean;
  saveAttempted: boolean;
  /** The query's Authorities after a pick, in the order picked. */
  onChange: (picks: AuthorityRow[]) => void;
}

/**
 * Authority multi-select shared by both legs. The operator checks one or
 * more explicit trust anchors — **Issuers** (configured Departments) or
 * **Authorities** (records from the Authorities register) — whose literal
 * DIDs are written verbatim: one as `query.authority_id`, several as
 * `query.authority_ids` in the order picked, and OPA gets one result each.
 *
 * On the caller leg the templates (the verified-issuer default and the
 * sending-gateway DID) are offered too and combine with the literal DIDs
 * like any other pick. While nothing is stored the default shows as
 * checked, so a pick is added beside it.
 *
 * Storing a literal DID (rather than a `{{ input.agent.provider_did }}`
 * template) means the runtime never resolves provider metadata off an
 * agent card / request payload. On the caller leg that avoids depending
 * on the caller's trust-registry extension (which may be absent when the
 * payload carries only an identity credential); on the target leg it is
 * both a trust-model requirement (the called party must not assert who
 * vouches for it) and the fix for the `TRUST_REGISTRY_METADATA_UNAVAILABLE`
 * gate that blocked checks whenever the card carried no trust-registry
 * metadata.
 *
 * Issuers and Authorities are grouped under disabled header rows. A DID
 * present in both registers is shown only under Issuers (issuers win on
 * collision). A stored legacy `{{ … }}` template or JSON-API-authored DID
 * outside both registers shows as a checked "… (from JSON API)" option, and
 * a stored Authority the loaded register no longer has as a checked
 * "Deleted Authority" option, marked invalid, with the Configuration
 * required warning; unchecking either removes it. When neither register
 * has entries and nothing is stored, a locked read-only textbox prompts the
 * operator to configure a Department or Authority.
 *
 * Picking an Issuer records `'issuer'` as its source, an Authority
 * `'authority'`, and a template none. There is no limit on how many are
 * picked.
 */
const IssuerAuthorityPicker: React.FC<IssuerAuthorityPickerProps> = ({
  testid,
  isApMa,
  queryConfig,
  issuers,
  authorities,
  authoritiesLoaded,
  saveAttempted,
  onChange,
}) => {
  const rows = authorityRows(queryConfig).filter(r => r.did.trim() !== '');
  const issuerDids = new Set(issuers.map(i => i.did));
  const authorityList = authorities
    .filter(a => !issuerDids.has(a.did))
    .map(a => ({ did: a.did, name: a.name, description: a.description }));
  const selected =
    isApMa && rows.length === 0 ? [AGENT_IDENTITY_ISSUER_DID_TEMPLATE] : rows.map(r => r.did);
  // Stored values neither register nor the templates offer.
  const extras = rows.flatMap(row => {
    if (isApMa && CALLER_TEMPLATES.has(row.did.trim())) return [];
    const selection = classifyTargetAuthoritySelection(
      row.did,
      issuers,
      authorities,
      row.source,
      authoritiesLoaded
    );
    return selection.kind === 'missing-authority' ||
      selection.kind === 'legacy-template' ||
      selection.kind === 'custom-did'
      ? [{ did: row.did, kind: selection.kind }]
      : [];
  });
  const missing = extras
    .filter(e => e.kind === 'missing-authority')
    .map((e, index) => ({ index, did: e.did }));

  if (!isApMa && issuers.length === 0 && authorityList.length === 0 && extras.length === 0) {
    return (
      <>
        <Form.Control
          size="sm"
          type="text"
          readOnly
          disabled
          value="No Issuers or Authorities configured"
          data-testid={`${testid}-locked`}
        />
        <Form.Text
          className="text-muted d-block mt-1"
          style={{ fontSize: '11px', wordBreak: 'break-all' }}
        >
          Add an{' '}
          <AddResourceLink to={deepLinks.issuer} testid={`${testid}-add-issuer-link`}>
            Issuer
          </AddResourceLink>{' '}
          or an{' '}
          <AddResourceLink to={deepLinks.authority} testid={`${testid}-add-authority-link`}>
            Authority
          </AddResourceLink>{' '}
          to select a trust anchor for the {isApMa ? 'caller' : 'target'}-leg Authority.
        </Form.Text>
      </>
    );
  }

  const options: Array<FormSelectOption<string>> = [];

  if (isApMa) {
    options.push({
      value: AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
      label: 'Agent identity credential issuer (default)',
      description: "The verified issuer of the caller's agent identity credential.",
    });
    options.push({
      value: INPUT_GATEWAY_SOURCE_ID_TEMPLATE,
      label: 'Sending gateway DID (fabric-inbound)',
      description:
        'The DID of the sending gateway on the fabric-inbound path. Only populated when the request arrived via `fabric://`; on direct inbound the query denies fail-safe.',
    });
  }
  // Group headers only earn their keep when BOTH categories are present —
  // a lone "Issuers" (or "Authorities") label above a single flat list
  // adds no information, so with one category we drop the header and the
  // per-item indent entirely.
  const showGroupHeaders = issuers.length > 0 && authorityList.length > 0;
  if (issuers.length > 0) {
    if (showGroupHeaders) {
      options.push({ value: GRP_ISSUERS, label: 'Issuers', disabled: true });
    }
    for (const issuer of issuers) {
      options.push({
        value: issuer.did,
        label: issuer.name,
        description: issuer.description || topAndTail(issuer.did, 16, 12),
        indent: showGroupHeaders,
      });
    }
  }
  if (authorityList.length > 0) {
    if (showGroupHeaders) {
      options.push({ value: GRP_AUTHORITIES, label: 'Authorities', disabled: true });
    }
    for (const authority of authorityList) {
      options.push({
        value: authority.did,
        label: authority.name,
        description: authority.description || topAndTail(authority.did, 16, 12),
        indent: showGroupHeaders,
      });
    }
  }
  for (const extra of extras) {
    if (options.some(o => o.value === extra.did)) continue;
    options.push({
      value: extra.did,
      label:
        extra.kind === 'missing-authority'
          ? 'Deleted Authority'
          : extra.kind === 'legacy-template'
            ? 'Legacy template (from JSON API)'
            : 'Custom DID (from JSON API)',
      description: extra.kind === 'legacy-template' ? extra.did : topAndTail(extra.did, 16, 12),
      indent: showGroupHeaders,
    });
  }
  const handleToggle = (value: string) => {
    if (value === GRP_ISSUERS || value === GRP_AUTHORITIES) return;
    // The shown selection, including the caller-leg default while nothing is stored.
    const current: AuthorityRow[] = selected.map(did => rows.find(r => r.did === did) ?? { did });
    if (selected.includes(value)) {
      onChange(current.filter(r => r.did !== value));
      return;
    }
    const pick: AuthorityRow = CALLER_TEMPLATES.has(value)
      ? { did: value }
      : { did: value, source: issuerDids.has(value) ? 'issuer' : 'authority' };
    onChange([...current, pick]);
  };

  return (
    <>
      <FormMultiSelect<string>
        values={selected}
        options={options}
        onToggle={handleToggle}
        isInvalid={
          (saveAttempted && queryAuthorityMissing(queryConfig, isApMa)) || missing.length > 0
        }
        placeholder="Select Issuers or Authorities…"
        testid={testid}
      />
      {missing.length > 0 && (
        <MissingAuthorityWarning
          testid={`${testid}-missing`}
          element="trust-check"
          missing={missing}
        />
      )}
      <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '11px' }}>
        {isApMa
          ? 'Choose the trust anchors the caller is checked against. By default, this is the cryptographically verified issuer of the caller’s agent identity credential.'
          : 'Choose the trust anchors the target is checked against. Their DIDs are stored directly, so the gateway never derives the authority from the target’s own agent card. If a picked Authority is deleted later, its check fails until you pick another.'}
      </Form.Text>
      {rows.length > 1 && (
        <Form.Text
          className="text-muted d-block"
          style={{ fontSize: '11px' }}
          data-testid={`${testid}-count`}
        >
          {rows.length} Authorities, one result each, in the order picked
        </Form.Text>
      )}
    </>
  );
};

export default TrustCheckQueryForm;
