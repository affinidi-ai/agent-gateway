import React from 'react';
import { Form } from 'react-bootstrap';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import { topAndTail } from '../../../../utils/stringUtils';
import { deepLinks } from '../../../../utils/deepLinks';
import AddResourceLink from '../../../shared/AddResourceLink';
import FormSelect, { type FormSelectOption } from '../../../shared/FormSelect';
import AuthorityListEditor from './AuthorityListEditor';
import { RECORD_TYPE } from './TrustCheckQueryList';
import {
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

const RECORD_TYPES: ReadonlyArray<{
  value: TrustCheckRecordType;
  label: string;
  icon: string;
  description: string;
}> = (['recognition', 'authorization'] as const).map(value => ({
  value,
  ...RECORD_TYPE[value],
  description: `Query a ${value} record from the Trust Registry`,
}));

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
  /** Replace the whole query, for an Authority change that also drops fields. */
  replaceQueryAt: (index: number, next: TrustCheckQueryConfig) => void;
  /** Values the query held when the editor opened; any other listed Authority is marked New. */
  baselineDids?: ReadonlySet<string>;
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
  replaceQueryAt,
  baselineDids,
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
    <div data-testid={tid('form')}>
      <div className="row g-3">
        <div className="col-auto">
          <div className="form-label fw-bold" id={tid('type-label')}>
            Record type
          </div>
          <div
            className="btn-group btn-group-sm"
            role="group"
            aria-labelledby={tid('type-label')}
            data-testid={tid('type')}
          >
            {RECORD_TYPES.map(option => (
              <button
                key={option.value}
                type="button"
                className={`btn btn-outline-primary${queryType === option.value ? ' active' : ''}`}
                aria-pressed={queryType === option.value}
                title={option.description}
                onClick={() => handleQueryTypeChangeAt(index, option.value)}
                data-testid={tid(`type-${option.value}`)}
              >
                <i className={`fas ${option.icon} me-1`} aria-hidden="true" />
                {option.label}
              </button>
            ))}
          </div>
        </div>

        <div className="col trust-check-registry-field">
          <Form.Label className="fw-bold">Trust registry</Form.Label>
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
          {loadError && <Form.Text className="text-danger">{loadError}</Form.Text>}
          {!loadError && (
            <Form.Text className="text-muted d-block">
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
          <AuthorityListEditor
            tidPrefix={`trust-check-query-${index}`}
            isApMa={isApMa}
            queryConfig={queryConfig}
            issuers={issuers}
            authorities={authorities}
            authoritiesLoaded={authoritiesLoaded}
            saveAttempted={saveAttempted}
            baselineDids={baselineDids}
            onChange={next => replaceQueryAt(index, next)}
          />
        </div>

        <div className="col-12">
          <Form.Label className="fw-bold">Entity ID</Form.Label>
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
            <div className="col-12 col-md-6">
              <Form.Label className="fw-bold">
                Action <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
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

            <div className="col-12 col-md-6">
              <Form.Label className="fw-bold">
                Resource <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
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
            <div className="col-12 col-md-6">
              <Form.Label className="fw-bold">Action (optional)</Form.Label>
              <Form.Control
                type="text"
                value={sq.action || ''}
                placeholder="is (default)"
                onChange={e => updateQuerySubField(index, 'action', e.target.value)}
                data-testid={tid('action')}
              />
            </div>

            <div className="col-12 col-md-6">
              <Form.Label className="fw-bold">Resource (optional)</Form.Label>
              <Form.Control
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
 * Subject-picker dropdown for Entity ID. Renders one FormSelect option per
 * named subject (index 0 marked as default) with the short subject label as
 * the header and a plain-English explanation as the subheader. When the
 * stored value is not one of the named subjects, an additional disabled
 * option surfaces the JSON-API-authored custom value (the raw template / DID
 * as the subheader) so the operator can see what's stored but cannot
 * re-select it; picking a named subject overwrites it. The selected option's
 * description also renders on the FormSelect toggle, so no separate
 * below-field caption is required.
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

export default TrustCheckQueryForm;
