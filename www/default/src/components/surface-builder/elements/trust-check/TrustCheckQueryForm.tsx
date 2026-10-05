import React from 'react';
import { Form } from 'react-bootstrap';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import { topAndTail } from '../../../../utils/stringUtils';
import { deepLinks } from '../../../../utils/deepLinks';
import AddResourceLink from '../../../shared/AddResourceLink';
import FormSelect, { type FormSelectOption } from '../../../shared/FormSelect';
import {
  AGENT_IDENTITY_ISSUER_DID_TEMPLATE,
  INPUT_GATEWAY_SOURCE_ID_TEMPLATE,
  authorityNeedsSelection,
  classifyTargetAuthoritySelection,
  readSubjectPickerState,
  subjectDescription,
  subjectForTemplate,
  subjectLabel,
  templateForSubject,
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
  loadError: string | null;
  updateQueryAt: (index: number, patch: Partial<TrustCheckQueryConfig>) => void;
  updateQuerySubField: (index: number, field: string, value: string) => void;
  updateAuthorityAt: (index: number, value: string) => void;
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
  loadError,
  updateQueryAt,
  updateQuerySubField,
  updateAuthorityAt,
  updateEntityAt,
  handleQueryTypeChangeAt,
  saveAttempted = false,
}) => {
  const queryType: TrustCheckRecordType =
    queryConfig.query_type === 'recognition' ? 'recognition' : 'authorization';
  const sq = queryConfig.query || {};
  const authorityValue: string = typeof sq.authority_id === 'string' ? sq.authority_id : '';
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
            storedValue={authorityValue}
            issuers={issuers}
            authorities={authorities}
            invalid={saveAttempted && authorityNeedsSelection(authorityValue, isApMa)}
            onChange={did => updateAuthorityAt(index, did)}
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
  testid: string;
  isApMa: boolean;
  storedValue: string;
  issuers: Issuer[];
  authorities: Authority[];
  invalid?: boolean;
  onChange: (did: string) => void;
}

/**
 * Authority picker shared by both legs. The operator chooses an explicit
 * trust anchor — an **Issuer** (a configured Department) or an
 * **Authority** (a record from the Authorities register) — whose literal
 * DID is written verbatim into `query.authority_id`.
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
 * Issuers and Authorities are grouped under disabled header rows
 * (`FormSelect` skips disabled options in nav and never commits them). A
 * DID present in both registers is shown only under Issuers (issuers win
 * on collision). A legacy `{{ … }}` template or a JSON-API-authored DID
 * outside both registers surfaces as a locked "… (from JSON API)" option
 * so the operator sees the stored value and can replace it. When neither
 * register has entries and nothing custom is stored, a locked read-only
 * textbox prompts the operator to configure a Department or Authority.
 */
const IssuerAuthorityPicker: React.FC<IssuerAuthorityPickerProps> = ({
  testid,
  isApMa,
  storedValue,
  issuers,
  authorities,
  invalid = false,
  onChange,
}) => {
  const mappedIssuers = issuers.map(d => ({
    did: d.did,
    name: d.name,
    description: d.description,
  }));
  const issuerDids = new Set(mappedIssuers.map(i => i.did));
  const authorityList = authorities
    .filter(a => !issuerDids.has(a.did))
    .map(a => ({ did: a.did, name: a.name, description: a.description }));
  const trimmed = storedValue.trim();
  const isVerifiedIssuerDefault =
    isApMa && (trimmed === '' || trimmed === AGENT_IDENTITY_ISSUER_DID_TEMPLATE);
  // Known caller-leg templates that appear as first-class picker options —
  // treated as valid selections rather than "custom (from JSON API)".
  const isKnownCallerTemplate =
    isApMa &&
    (trimmed === AGENT_IDENTITY_ISSUER_DID_TEMPLATE ||
      trimmed === INPUT_GATEWAY_SOURCE_ID_TEMPLATE);
  const effectiveValue =
    isApMa && trimmed === '' ? AGENT_IDENTITY_ISSUER_DID_TEMPLATE : storedValue;
  const selection = classifyTargetAuthoritySelection(storedValue, issuers, authorityList);
  const hasCustom =
    !isVerifiedIssuerDefault &&
    !isKnownCallerTemplate &&
    (selection.kind === 'legacy-template' || selection.kind === 'custom-did');

  if (!isApMa && issuers.length === 0 && authorityList.length === 0 && !hasCustom) {
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
  if (hasCustom) {
    options.push({
      value: storedValue,
      label:
        selection.kind === 'legacy-template'
          ? 'Legacy template (from JSON API)'
          : 'Custom DID (from JSON API)',
      description:
        selection.kind === 'legacy-template' ? selection.template : topAndTail(storedValue, 16, 12),
      disabled: true,
      indent: showGroupHeaders,
    });
  }

  const handleChange = (next: string) => {
    if (next === GRP_ISSUERS || next === GRP_AUTHORITIES) return;
    onChange(next);
  };

  return (
    <>
      <FormSelect<string>
        value={effectiveValue}
        options={options}
        onChange={handleChange}
        isInvalid={invalid}
        placeholder="Select an Issuer or Authority…"
        testid={testid}
      />
      <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '11px' }}>
        {isApMa
          ? 'Pick the trust anchor the caller is checked against. The default resolves to the cryptographically-verified issuer of the caller’s agent identity credential; pick an Issuer or Authority to pin an explicit DID instead.'
          : 'Pick the trust anchor the target is checked against. Its DID is stored directly, so the gateway never derives the authority from the target’s own agent card.'}
      </Form.Text>
    </>
  );
};

export default TrustCheckQueryForm;
