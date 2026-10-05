import React from 'react';
import { Form } from 'react-bootstrap';
import type { Authority, Issuer, TrustRegistry } from '../../../../types';
import { topAndTail } from '../../../../utils/stringUtils';
import { deepLinks } from '../../../../utils/deepLinks';
import AddResourceLink from '../../../shared/AddResourceLink';
import FormSelect, { type FormSelectOption } from '../../../shared/FormSelect';
import {
  SURFACE_ISSUER_DID_TEMPLATE,
  type CustomResource,
  type EntityTarget,
  type TrustRecorderEntry,
} from './definition';

interface TrustRecorderEntryFormProps {
  entry: TrustRecorderEntry;
  index: number;
  registries: TrustRegistry[];
  issuers: Issuer[];
  authorities: Authority[];
  loadError: string | null;
  issuersLoadError: string | null;
  authoritiesLoadError: string | null;
  updateEntry: (index: number, patch: Partial<TrustRecorderEntry>) => void;
  updateCustomResourceAt: (
    index: number,
    resourceIdx: number,
    patch: Partial<CustomResource>
  ) => void;
  addCustomResource: (index: number) => void;
  removeCustomResourceAt: (index: number, resourceIdx: number) => void;
  /**
   * When `true`, per-field validation errors (missing Trust Registry /
   * Issuer / Authority, or no record source enabled) surface their
   * `isInvalid` state and inline feedback. Set by the fullscreen panel
   * on the first Save click so the operator doesn't see red errors
   * before they've tried to save.
   */
  saveAttempted?: boolean;
}

const TrustRecorderEntryForm: React.FC<TrustRecorderEntryFormProps> = ({
  entry,
  index,
  registries,
  issuers,
  authorities,
  loadError,
  issuersLoadError,
  authoritiesLoadError,
  updateEntry,
  updateCustomResourceAt,
  addCustomResource,
  removeCustomResourceAt,
  saveAttempted = false,
}) => {
  const tid = (suffix: string) => `trust-recorder-entry-${index}-${suffix}`;
  const hasCompleteCustomResource = entry.custom_resources.some(
    r =>
      r.action.trim().length > 0 && r.resource.trim().length > 0 && r.record_type.trim().length > 0
  );
  const noRecordSource = !entry.include_owned_agent && !hasCompleteCustomResource;

  // Build the Trust Registry option list — mirrors the Trust Check
  // fullscreen dropdown so the same connected / description / DID
  // conventions apply here.
  const registryOptions: FormSelectOption<string>[] = registries.map(r => {
    const detail = r.description || (r.main_did ? topAndTail(r.main_did, 16, 12) : '');
    const description =
      r.connection_status !== 'connected'
        ? detail
          ? `Not connected (${r.connection_status}) · ${detail}`
          : `Not connected (${r.connection_status})`
        : detail || undefined;
    return { value: r.id, label: r.name, description };
  });

  // Issuer options: Issuers only. Description falls back to the
  // truncated DID when no `description` is set, matching the Trust
  // Registry pattern.
  const issuerOptions: FormSelectOption<string>[] = issuers.map(d => ({
    value: d.did,
    label: d.name,
    description: d.description || (d.did ? topAndTail(d.did, 16, 12) : undefined),
  }));

  // Authority options: flatten the two sources (Authorities register +
  // Issuer-derived authority DIDs) into a single FormSelect list.
  // DIDs from the Authority register take precedence over the same DID
  // derived from a Issuer. Source is disambiguated via the option
  // description prefix.
  const authorityFromAuthorities: FormSelectOption<string>[] = authorities
    .filter(a => !!a.did)
    .map(a => ({
      value: a.did,
      label: a.name,
      description: a.description || (a.did ? topAndTail(a.did, 16, 12) : undefined),
    }));
  const authorityDidSet = new Set(authorityFromAuthorities.map(o => o.value));
  const authorityFromIssuers: FormSelectOption<string>[] = issuers
    .filter(d => !!d.authority_did && !authorityDidSet.has(d.authority_did as string))
    .map(d => {
      const detail = d.description || topAndTail(d.authority_did as string, 16, 12);
      return {
        value: d.authority_did as string,
        label: d.name,
        description: `Via Issuer · ${detail}`,
      };
    });
  const authorityOptions: FormSelectOption<string>[] = [
    ...authorityFromAuthorities,
    ...authorityFromIssuers,
  ];
  const hasAnyAuthorityOptions = authorityOptions.length > 0;
  const storedAuthority = entry.authority_did;
  const authorityMode: 'explicit' | 'surface-issuer' =
    storedAuthority === SURFACE_ISSUER_DID_TEMPLATE ? 'surface-issuer' : 'explicit';
  const explicitAuthority = authorityMode === 'explicit' ? storedAuthority : '';
  const storedAuthorityIsKnown =
    !explicitAuthority || authorityOptions.some(o => o.value === explicitAuthority);
  const authorityOptionsWithCustom: FormSelectOption<string>[] = storedAuthorityIsKnown
    ? authorityOptions
    : [
        ...authorityOptions,
        {
          value: explicitAuthority,
          label: 'Custom (from JSON API)',
          description: explicitAuthority ? topAndTail(explicitAuthority, 16, 12) : undefined,
          disabled: true,
        },
      ];

  return (
    <div className="p-3" data-testid={tid('form')}>
      <div className="row g-3">
        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Trust Registry</Form.Label>
          <FormSelect<string>
            value={entry.trust_registry_id || ''}
            options={registryOptions}
            onChange={next => updateEntry(index, { trust_registry_id: next })}
            placeholder="Select a trust registry"
            disabled={registries.length === 0}
            isInvalid={saveAttempted && !entry.trust_registry_id}
            testid={tid('registry')}
          />
          {saveAttempted && !entry.trust_registry_id && (
            <div className="invalid-feedback d-block">Select a Trust Registry to record into.</div>
          )}
          {loadError && (
            <Form.Text className="text-danger d-block" style={{ fontSize: '11px' }}>
              {loadError}
            </Form.Text>
          )}
          {!loadError && (
            <Form.Text
              className="text-muted d-block"
              style={{ fontSize: '11px' }}
              data-testid={tid('registry-empty-hint')}
            >
              {registries.length === 0
                ? 'No Trust Registries configured yet. '
                : "Don't see the one you need? "}
              <AddResourceLink to={deepLinks.trustRegistry} testid={tid('add-registry-link')}>
                Add Trust Registry
              </AddResourceLink>
            </Form.Text>
          )}
        </div>

        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Issuer</Form.Label>
          <FormSelect<string>
            value={entry.issuer_did}
            options={issuerOptions}
            onChange={next => updateEntry(index, { issuer_did: next })}
            placeholder="Select an issuer"
            disabled={issuers.length === 0}
            isInvalid={saveAttempted && !entry.issuer_did}
            testid={tid('issuer')}
          />
          {saveAttempted && !entry.issuer_did && (
            <div className="invalid-feedback d-block">Select an Issuer to sign the records.</div>
          )}
          {issuersLoadError && (
            <Form.Text className="text-danger d-block" style={{ fontSize: '11px' }}>
              {issuersLoadError}
            </Form.Text>
          )}
          {!issuersLoadError && (
            <Form.Text
              className="text-muted d-block"
              style={{ fontSize: '11px' }}
              data-testid={tid('issuer-empty-hint')}
            >
              {issuers.length === 0
                ? 'No Issuers configured yet. '
                : "Don't see the one you need? "}
              <AddResourceLink to={deepLinks.issuer} testid={tid('add-issuer-link')}>
                Add Issuer
              </AddResourceLink>
            </Form.Text>
          )}
          <Form.Text className="text-muted d-block" style={{ fontSize: '11px' }}>
            Issuer that signs the records written to this registry.
          </Form.Text>
        </div>

        <div className="col-12">
          <Form.Label className="fw-semibold small mb-1">Authority</Form.Label>
          <div className="d-flex gap-3 mb-2" data-testid={tid('authority-mode')}>
            <Form.Check
              type="radio"
              id={tid('authority-mode-explicit')}
              name={tid('authority-mode-group')}
              label={<span>Explicit DID</span>}
              checked={authorityMode === 'explicit'}
              onChange={() => {
                if (authorityMode === 'explicit') return;
                updateEntry(index, { authority_did: '' });
              }}
              data-testid={tid('authority-mode-explicit-radio')}
            />
            <Form.Check
              type="radio"
              id={tid('authority-mode-surface-issuer')}
              name={tid('authority-mode-group')}
              label={<span>Use surface Issuer</span>}
              checked={authorityMode === 'surface-issuer'}
              onChange={() => {
                if (authorityMode === 'surface-issuer') return;
                updateEntry(index, { authority_did: SURFACE_ISSUER_DID_TEMPLATE });
              }}
              data-testid={tid('authority-mode-surface-issuer-radio')}
            />
          </div>
          {authorityMode === 'explicit' ? (
            <>
              <FormSelect<string>
                value={explicitAuthority}
                options={authorityOptionsWithCustom}
                onChange={next => updateEntry(index, { authority_did: next })}
                placeholder="Select an authority"
                disabled={authorityOptionsWithCustom.length === 0}
                isInvalid={saveAttempted && !explicitAuthority}
                testid={tid('authority')}
              />
              {saveAttempted && !explicitAuthority && (
                <div className="invalid-feedback d-block">
                  Select an Authority (or an Issuer authority) to act as the trust anchor.
                </div>
              )}
              {issuersLoadError && (
                <Form.Text className="text-danger d-block" style={{ fontSize: '11px' }}>
                  {issuersLoadError}
                </Form.Text>
              )}
              {authoritiesLoadError && (
                <Form.Text className="text-danger d-block" style={{ fontSize: '11px' }}>
                  {authoritiesLoadError}
                </Form.Text>
              )}
              {!issuersLoadError && !authoritiesLoadError && (
                <Form.Text
                  className="text-muted d-block"
                  style={{ fontSize: '11px' }}
                  data-testid={tid('authority-empty-hint')}
                >
                  {!hasAnyAuthorityOptions
                    ? 'No Authorities configured yet. '
                    : "Don't see the one you need? "}
                  <AddResourceLink to={deepLinks.authority} testid={tid('add-authority-link')}>
                    Add Authority
                  </AddResourceLink>
                </Form.Text>
              )}
              <Form.Text className="text-muted d-block" style={{ fontSize: '11px' }}>
                Trust anchor asserting these records. Pick an Authority or an Issuer. Required.
              </Form.Text>
            </>
          ) : (
            <div data-testid={tid('authority-surface-issuer')}>
              <Form.Control
                size="sm"
                type="text"
                readOnly
                disabled
                value={SURFACE_ISSUER_DID_TEMPLATE}
                data-testid={tid('authority-surface-issuer-value')}
              />
              <Form.Text className="text-muted d-block" style={{ fontSize: '11px' }}>
                Records will be written with <code>authority_id</code> resolved at write time to the
                surface's Issuer DID. Matches downstream Trust Check queries whose Authority is
                <em> the verified identity credential issuer</em>. If the surface has no Issuer
                configured, the entry is skipped (fail-safe) with a WARN.
              </Form.Text>
            </div>
          )}
        </div>
      </div>

      <div className="mt-3">
        <Form.Label className="fw-semibold small mb-2">Built-in triple</Form.Label>
        <Form.Check
          type="checkbox"
          id={tid('include-owned-agent')}
          label={
            <>
              <strong>[Authority]</strong> Agent DID <em>is</em> <code>ownedAgent</code>
              <span className="text-muted ms-2" style={{ fontSize: '11px' }}>
                (Agent DID auto-filled from the response)
              </span>
            </>
          }
          checked={entry.include_owned_agent}
          onChange={e => updateEntry(index, { include_owned_agent: e.target.checked })}
          data-testid={tid('owned-agent')}
        />
      </div>

      <div className="mt-3">
        <Form.Label className="fw-semibold small mb-2">
          Custom resources
          <span className="text-muted ms-2" style={{ fontSize: '11px', fontWeight: 400 }}>
            <code>[Authority]</code> <em>action</em> <code>&lt;resource&gt;</code>, entity per row
          </span>
        </Form.Label>
        {entry.custom_resources.length === 0 && (
          <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '11px' }}>
            No custom resources. Add one to record an additional action/resource per agent or
            issuer.
          </Form.Text>
        )}
        {entry.custom_resources.map((resource, resourceIdx) => (
          <div key={resourceIdx} className="d-flex gap-2 mb-2 align-items-start">
            <Form.Control
              size="sm"
              type="text"
              placeholder="action (e.g. is)"
              value={resource.action}
              onChange={e => updateCustomResourceAt(index, resourceIdx, { action: e.target.value })}
              data-testid={tid(`custom-resource-${resourceIdx}-action`)}
            />
            <Form.Control
              size="sm"
              type="text"
              placeholder="resource (e.g. paymentAgent)"
              value={resource.resource}
              onChange={e =>
                updateCustomResourceAt(index, resourceIdx, { resource: e.target.value })
              }
              data-testid={tid(`custom-resource-${resourceIdx}-resource`)}
            />
            <div style={{ maxWidth: '140px' }}>
              <Form.Label
                htmlFor={tid(`custom-resource-${resourceIdx}-target`)}
                className="text-muted mb-1 d-block"
                style={{ fontSize: '10px' }}
              >
                Entity Target
              </Form.Label>
              <Form.Select
                id={tid(`custom-resource-${resourceIdx}-target`)}
                size="sm"
                value={resource.entity_target}
                onChange={e =>
                  updateCustomResourceAt(index, resourceIdx, {
                    entity_target: e.target.value as EntityTarget,
                  })
                }
                title="Whose DID this record is about: the agent being recorded, or the issuer signing it."
                data-testid={tid(`custom-resource-${resourceIdx}-target`)}
              >
                <option value="agent">Agent DID</option>
                <option value="issuer">Issuer DID</option>
              </Form.Select>
            </div>
            <div style={{ maxWidth: '150px' }}>
              <Form.Label
                htmlFor={tid(`custom-resource-${resourceIdx}-record-type`)}
                className="text-muted mb-1 d-block"
                style={{ fontSize: '10px' }}
              >
                Record Type
              </Form.Label>
              <Form.Select
                id={tid(`custom-resource-${resourceIdx}-record-type`)}
                size="sm"
                value={resource.record_type}
                onChange={e =>
                  updateCustomResourceAt(index, resourceIdx, {
                    record_type: e.target.value,
                  })
                }
                title="Recognition records who an entity is; authorization records what it's allowed to do."
                data-testid={tid(`custom-resource-${resourceIdx}-record-type`)}
              >
                <option value="recognition">recognition</option>
                <option value="authorization">authorization</option>
              </Form.Select>
            </div>
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => removeCustomResourceAt(index, resourceIdx)}
              title="Remove custom resource"
              data-testid={tid(`custom-resource-${resourceIdx}-remove`)}
            >
              <i className="fas fa-times" />
            </button>
          </div>
        ))}
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          onClick={() => addCustomResource(index)}
          data-testid={tid('add-custom-resource')}
        >
          <i className="fas fa-plus me-1" /> Add custom resource
        </button>
      </div>

      {saveAttempted && noRecordSource && (
        <div
          className="alert alert-danger py-1 px-2 mt-3 mb-0"
          style={{ fontSize: '11px' }}
          data-testid={tid('no-record-source-error')}
        >
          <i className="fas fa-exclamation-circle me-1" aria-hidden="true" />
          Enable the built-in <code>ownedAgent</code> triple or add at least one complete custom
          resource.
        </div>
      )}
    </div>
  );
};

export default TrustRecorderEntryForm;
