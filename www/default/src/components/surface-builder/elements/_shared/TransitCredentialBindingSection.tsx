import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import FieldHelp from '../../../shared/FieldHelp';

interface CredentialProviderOption {
  id: string;
  name: string;
  provider_id?: string;
  provider_type?: string;
  callback_url?: string;
}

export interface TransitCredentialsForm {
  credential_provider_id: string;
  scopes: string;
  consent_mode: 'on_demand' | 'pre_authorize';
  inject_as_type: 'bearer_header' | 'custom_header' | 'meta';
  inject_as_custom_name?: string;
  inject_as_custom_format?: string;
  inject_as_meta_field?: string;
}

export const EMPTY_TRANSIT_CREDENTIALS: TransitCredentialsForm = {
  credential_provider_id: '',
  scopes: '',
  consent_mode: 'on_demand',
  inject_as_type: 'bearer_header',
  inject_as_custom_format: 'token {value}',
};

/** Convert form-state to the runtime `TransitCredentials` shape. */
export function transitCredentialsFormToApi(f: TransitCredentialsForm | null | undefined): any {
  if (!f || !f.credential_provider_id) return undefined;
  const scopes = f.scopes
    .split(/[,\s]+/)
    .map(s => s.trim())
    .filter(Boolean);
  let inject_as: any = { type: 'bearer_header' };
  if (f.inject_as_type === 'custom_header') {
    inject_as = {
      type: 'custom_header',
      name: f.inject_as_custom_name ?? '',
      format: f.inject_as_custom_format ?? 'token {value}',
    };
  } else if (f.inject_as_type === 'meta') {
    inject_as = { type: 'meta', field: f.inject_as_meta_field ?? '' };
  }
  return {
    credential_provider_id: f.credential_provider_id,
    scopes,
    consent_mode: f.consent_mode,
    inject_as,
  };
}

/** Convert a runtime `TransitCredentials` slice back to form-state. */
export function transitCredentialsApiToForm(api: any): TransitCredentialsForm | null {
  if (!api || typeof api !== 'object' || !api.credential_provider_id) return null;
  let inject_as_type: TransitCredentialsForm['inject_as_type'] = 'bearer_header';
  let inject_as_custom_name: string | undefined;
  let inject_as_custom_format: string | undefined = 'token {value}';
  let inject_as_meta_field: string | undefined;
  if (api.inject_as?.type === 'custom_header') {
    inject_as_type = 'custom_header';
    inject_as_custom_name = api.inject_as.name ?? '';
    inject_as_custom_format = api.inject_as.format ?? 'token {value}';
  } else if (api.inject_as?.type === 'meta') {
    inject_as_type = 'meta';
    inject_as_meta_field = api.inject_as.field ?? '';
  }
  return {
    credential_provider_id: api.credential_provider_id,
    scopes: Array.isArray(api.scopes) ? api.scopes.join(', ') : '',
    consent_mode: api.consent_mode ?? 'on_demand',
    inject_as_type,
    inject_as_custom_name,
    inject_as_custom_format,
    inject_as_meta_field,
  };
}

interface Props {
  value: TransitCredentialsForm | null | undefined;
  onChange: (next: TransitCredentialsForm | null) => void;
}

/**
 * Surface-builder credential binding editor for a single Transit Point.
 * Maps to one optional `TransitCredentials` value
 * (`transit.points[i].transit_credentials`). Unlike the channel UI,
 * which supports an array of bindings, each TP carries at most one.
 */
const TransitCredentialBindingSection: React.FC<Props> = ({ value, onChange }) => {
  const [providers, setProviders] = useState<CredentialProviderOption[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    apiClient
      .fetch('/api/v1/credential-providers')
      .then(r => (r.ok ? r.json() : []))
      .then(data => {
        if (alive) setProviders(Array.isArray(data) ? data : []);
      })
      .catch(() => {})
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  const enabled = value !== null && value !== undefined;

  const toggle = () => {
    if (enabled) onChange(null);
    else onChange({ ...EMPTY_TRANSIT_CREDENTIALS });
  };

  const update = <K extends keyof TransitCredentialsForm>(
    field: K,
    v: TransitCredentialsForm[K]
  ) => {
    if (!value) return;
    onChange({ ...value, [field]: v });
  };

  return (
    <div className="config-section">
      <Form.Check
        type="switch"
        id="surface-tp-credential-binding-toggle"
        label="Inject outbound credential"
        checked={enabled}
        onChange={toggle}
      />
      <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
        Pull a credential from a configured provider and attach it to every outbound request through
        this transit point.
      </Form.Text>

      {enabled && value && (
        <div className="mt-2">
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0">Credential Provider</Form.Label>
            <Form.Select
              size="sm"
              value={value.credential_provider_id}
              onChange={e => update('credential_provider_id', e.target.value)}
              disabled={loading}
            >
              <option value="">{loading ? '-- Loading… --' : '-- Select provider --'}</option>
              {providers.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.provider_id ? ` (${p.provider_id})` : ''}
                </option>
              ))}
            </Form.Select>
            {(() => {
              const selected = providers.find(p => p.id === value.credential_provider_id);
              if (!selected) return null;
              const cb = selected.callback_url;
              return (
                <div className="outbound-credential-callback mt-2 p-2 small">
                  <div className="outbound-credential-callback-title">
                    <i className="fas fa-shield-halved me-1" />
                    Gateway-held credential callback URL
                  </div>
                  {cb ? (
                    <>
                      <div className="mb-1">OAuth callback URL configured on this provider:</div>
                      <div className="d-flex align-items-center gap-1 mb-2">
                        <code style={{ wordBreak: 'break-all', flex: 1 }}>{cb}</code>
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0"
                          title="Copy callback URL"
                          onClick={() => navigator.clipboard.writeText(cb)}
                        >
                          <i className="fas fa-copy" />
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="mb-1 fst-italic">
                      No callback URL configured on this provider yet.
                    </div>
                  )}
                  <div>
                    Tokens returned to this callback are stored on the gateway and re-injected
                    automatically onto outbound calls. The calling agent never sees the user&apos;s
                    credentials.
                  </div>
                </div>
              );
            })()}
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0">Scopes</Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={value.scopes}
              onChange={e => update('scopes', e.target.value)}
              placeholder="repo, read:user (empty = provider defaults)"
            />
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0 d-flex align-items-center justify-content-between">
              <span>Consent Mode</span>
              <a
                href="/guides/credential-delegation.html#consent-modes-explained"
                target="_blank"
                rel="noreferrer"
                title="What do these consent modes mean?"
                className="text-decoration-none"
                style={{ fontSize: '0.85em' }}
              >
                <i className="fas fa-circle-question me-1" />
                Help
              </a>
            </Form.Label>
            <Form.Select
              size="sm"
              value={value.consent_mode}
              onChange={e =>
                update('consent_mode', e.target.value as TransitCredentialsForm['consent_mode'])
              }
            >
              <option value="on_demand">On demand (signal consent_required)</option>
              <option value="pre_authorize">Pre-authorize (block until granted)</option>
            </Form.Select>
          </Form.Group>

          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-0">
              <Form.Label className="small text-muted mb-0">Inject As</Form.Label>
              <FieldHelp
                testId="field-help-transit-credential-binding-section-inject-as"
                ariaLabel="About Inject As"
              >
                Bearer header sends the credential in a standard <code>Authorization: Bearer</code>{' '}
                header (most common). Custom header sends it in a header you name, in a format you
                control. JSON-RPC <code>_meta</code> attaches it inside the request&apos;s{' '}
                <code>_meta</code> field instead of a header, for protocols/tools that expect it
                there.
              </FieldHelp>
            </div>
            <Form.Select
              size="sm"
              value={value.inject_as_type}
              onChange={e =>
                update('inject_as_type', e.target.value as TransitCredentialsForm['inject_as_type'])
              }
            >
              <option value="bearer_header">Bearer header</option>
              <option value="custom_header">Custom header</option>
              <option value="meta">JSON-RPC _meta</option>
            </Form.Select>
          </Form.Group>

          {value.inject_as_type === 'custom_header' && (
            <>
              <Form.Group className="mb-1">
                <Form.Label className="small text-muted mb-0">Header name</Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  value={value.inject_as_custom_name ?? ''}
                  onChange={e => update('inject_as_custom_name', e.target.value)}
                  placeholder="X-GitHub-Token"
                />
              </Form.Group>
              <Form.Group className="mb-1">
                <Form.Label className="small text-muted mb-0">Header format</Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  value={value.inject_as_custom_format ?? ''}
                  onChange={e => update('inject_as_custom_format', e.target.value)}
                  placeholder="token {value}"
                />
              </Form.Group>
            </>
          )}

          {value.inject_as_type === 'meta' && (
            <Form.Group className="mb-1">
              <Form.Label className="small text-muted mb-0">Meta field name</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                value={value.inject_as_meta_field ?? ''}
                onChange={e => update('inject_as_meta_field', e.target.value)}
                placeholder="oauth_token"
              />
            </Form.Group>
          )}
        </div>
      )}
    </div>
  );
};

export default TransitCredentialBindingSection;
