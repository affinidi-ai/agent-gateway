import React, { useEffect, useState } from 'react';
import { Form, Button } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import FieldHelp from '../../../shared/FieldHelp';

interface CredentialProviderOption {
  id: string;
  name: string;
  provider_id?: string;
  provider_type?: string;
  callback_url?: string;
}

/**
 * Form-state row for one outbound credential binding. Mirrors the
 * runtime `OutboundCredentialBinding` shape.
 *
 * `required_for_mode = 'all'` injects the credential on every outbound
 * request; `'tools'` restricts injection to the comma-separated
 * `required_for_tools` list (typed as MCP tool names).
 */
export interface OutboundCredentialFormRow {
  credential_provider_id: string;
  scopes: string;
  consent_mode: 'on_demand' | 'pre_authorize' | 'elicit';
  elicit_timeout_secs?: number;
  elicit_fallback?: 'on_demand' | 'fail';
  required_for_mode: 'all' | 'tools';
  required_for_tools?: string;
  inject_as_type: 'bearer_header' | 'custom_header' | 'meta';
  inject_as_custom_name?: string;
  inject_as_custom_format?: string;
  inject_as_meta_field?: string;
}

const EMPTY_ROW: OutboundCredentialFormRow = {
  credential_provider_id: '',
  scopes: '',
  consent_mode: 'on_demand',
  elicit_timeout_secs: 300,
  elicit_fallback: 'on_demand',
  required_for_mode: 'all',
  inject_as_type: 'bearer_header',
  inject_as_custom_format: 'token {value}',
};

/** Convert a form row to the runtime `OutboundCredentialBinding` shape. */
export function outboundCredentialFormToApi(f: OutboundCredentialFormRow): any | undefined {
  if (!f.credential_provider_id) return undefined;
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
  let required_for: any = 'all';
  if (f.required_for_mode === 'tools') {
    const tools = (f.required_for_tools ?? '')
      .split(/[,\s]+/)
      .map(s => s.trim())
      .filter(Boolean);
    // Empty tools list silently degrades to 'all' rather than emitting an
    // empty Tools(_) which the runtime would treat as never-match.
    required_for = tools.length > 0 ? { tools } : 'all';
  }
  return {
    credential_provider_id: f.credential_provider_id,
    scopes,
    required_for,
    consent_mode: f.consent_mode,
    ...(f.consent_mode === 'elicit' && {
      elicit_timeout_secs: f.elicit_timeout_secs ?? 300,
      elicit_fallback: f.elicit_fallback ?? 'on_demand',
    }),
    inject_as,
  };
}

/** Convert a runtime `OutboundCredentialBinding` back to a form row. */
export function outboundCredentialApiToForm(api: any): OutboundCredentialFormRow | null {
  if (!api || typeof api !== 'object' || !api.credential_provider_id) return null;
  let inject_as_type: OutboundCredentialFormRow['inject_as_type'] = 'bearer_header';
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
  let required_for_mode: OutboundCredentialFormRow['required_for_mode'] = 'all';
  let required_for_tools: string | undefined;
  if (
    api.required_for &&
    typeof api.required_for === 'object' &&
    Array.isArray(api.required_for.tools)
  ) {
    required_for_mode = 'tools';
    required_for_tools = api.required_for.tools.join(', ');
  }
  return {
    credential_provider_id: api.credential_provider_id,
    scopes: Array.isArray(api.scopes) ? api.scopes.join(', ') : '',
    consent_mode: api.consent_mode ?? 'on_demand',
    elicit_timeout_secs: api.elicit_timeout_secs ?? 300,
    elicit_fallback: api.elicit_fallback ?? 'on_demand',
    required_for_mode,
    required_for_tools,
    inject_as_type,
    inject_as_custom_name,
    inject_as_custom_format,
    inject_as_meta_field,
  };
}

interface Props {
  rows: OutboundCredentialFormRow[];
  onChange: (next: OutboundCredentialFormRow[]) => void;
}

/**
 * Multi-binding editor for surface-level `outbound_credentials`. Each
 * row binds a credential provider for outbound delegation; the gateway
 * injects cached tokens or signals consent_required when missing.
 */
const OutboundCredentialsListSection: React.FC<Props> = ({ rows, onChange }) => {
  const [providers, setProviders] = useState<CredentialProviderOption[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const response = await apiClient.fetch('/api/v1/credential-providers');
        if (!response.ok) {
          console.error(
            '[OutboundCredentialsListSection] credential-providers fetch failed:',
            response.status,
            response.statusText
          );
          return;
        }
        const data = await response.json();
        if (alive) setProviders(Array.isArray(data) ? data : []);
      } catch (e) {
        console.error('[OutboundCredentialsListSection] failed to load credential providers:', e);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const addRow = () => onChange([...rows, { ...EMPTY_ROW }]);

  const removeRow = (idx: number) => onChange(rows.filter((_, i) => i !== idx));

  const updateRow = (idx: number, patch: Partial<OutboundCredentialFormRow>) => {
    onChange(rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  };

  return (
    <div>
      <Form.Text className="text-muted d-block mb-2" style={{ fontSize: '10px' }}>
        Bind credential providers to this surface for outbound delegation. The gateway will inject
        cached tokens or signal <code>consent_required</code> back to the caller when a token is
        missing.
      </Form.Text>

      {rows.length === 0 && (
        <div className="text-muted small fst-italic mb-2">
          No outbound credentials bound. Click <em>Add credential</em> to create one.
        </div>
      )}

      {rows.map((row, idx) => (
        <div
          key={idx}
          className="border rounded p-2 mb-2 position-relative"
          style={{ background: 'rgba(0,0,0,0.02)' }}
        >
          <button
            type="button"
            className="btn btn-link btn-sm text-decoration-none p-0 text-danger position-absolute"
            style={{ top: '0.5rem', right: '0.5rem', zIndex: 1 }}
            onClick={() => removeRow(idx)}
            title="Remove binding"
          >
            <i className="fas fa-trash" />
          </button>

          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0">Credential Provider</Form.Label>
            <Form.Select
              size="sm"
              value={row.credential_provider_id}
              onChange={e => updateRow(idx, { credential_provider_id: e.target.value })}
              disabled={loading}
            >
              <option value="">{loading ? '-- Loading… --' : '-- Select provider --'}</option>
              {providers.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.provider_id ? ` (${p.provider_id})` : ''}
                </option>
              ))}
              {row.credential_provider_id &&
                !providers.some(p => p.id === row.credential_provider_id) && (
                  <option value={row.credential_provider_id}>
                    {row.credential_provider_id} (not in list)
                  </option>
                )}
            </Form.Select>
            {!loading && (
              <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
                {providers.length === 0
                  ? 'No credential providers configured yet. '
                  : "Don't see the one you need? "}
                <AddResourceLink
                  to={deepLinks.credentialProvider}
                  testid={`outbound-credentials-${idx}-add-provider-link`}
                >
                  Add credential provider
                </AddResourceLink>
              </Form.Text>
            )}
            {(() => {
              const selected = providers.find(p => p.id === row.credential_provider_id);
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
                    automatically onto outbound calls. The calling agent never sees the user's
                    credentials.
                  </div>
                </div>
              );
            })()}
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0">
              Scopes - leave empty for provider defaults
            </Form.Label>
            <Form.Control
              size="sm"
              type="text"
              value={row.scopes}
              onChange={e => updateRow(idx, { scopes: e.target.value })}
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
              value={row.consent_mode}
              onChange={e =>
                updateRow(idx, {
                  consent_mode: e.target.value as OutboundCredentialFormRow['consent_mode'],
                })
              }
            >
              <option value="on_demand">On demand (signal consent_required)</option>
              <option value="pre_authorize">Pre-authorize (block until granted)</option>
              <option value="elicit">Elicit (MCP elicitation/create prompt)</option>
            </Form.Select>
            {row.consent_mode === 'elicit' && (
              <div className="mt-2 ps-2" style={{ borderLeft: '2px solid rgba(0,0,0,0.1)' }}>
                <Form.Label className="small text-muted mb-0">Elicit timeout (seconds)</Form.Label>
                <Form.Control
                  size="sm"
                  type="number"
                  min={1}
                  value={row.elicit_timeout_secs ?? 300}
                  onChange={e =>
                    updateRow(idx, { elicit_timeout_secs: parseInt(e.target.value, 10) || 300 })
                  }
                />
                <Form.Label className="small text-muted mb-0 mt-2">
                  Fallback when client doesn't support elicitation
                </Form.Label>
                <Form.Select
                  size="sm"
                  value={row.elicit_fallback ?? 'on_demand'}
                  onChange={e =>
                    updateRow(idx, {
                      elicit_fallback: e.target
                        .value as OutboundCredentialFormRow['elicit_fallback'],
                    })
                  }
                >
                  <option value="on_demand">On demand (signal consent_required)</option>
                  <option value="fail">Fail (return not_applicable)</option>
                </Form.Select>
              </div>
            )}
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-0">Required For</Form.Label>
            <Form.Select
              size="sm"
              value={row.required_for_mode}
              onChange={e =>
                updateRow(idx, {
                  required_for_mode: e.target
                    .value as OutboundCredentialFormRow['required_for_mode'],
                })
              }
            >
              <option value="all">All outbound requests</option>
              <option value="tools">Specific MCP tools only</option>
            </Form.Select>
            {row.required_for_mode === 'tools' && (
              <Form.Control
                size="sm"
                type="text"
                className="mt-1"
                value={row.required_for_tools ?? ''}
                onChange={e => updateRow(idx, { required_for_tools: e.target.value })}
                placeholder="create_issue, update_pr (comma-separated tool names)"
              />
            )}
          </Form.Group>

          <Form.Group className="mb-2">
            <div className="d-flex align-items-center gap-1 mb-0">
              <Form.Label className="small text-muted mb-0">Inject As</Form.Label>
              <FieldHelp
                testId="field-help-outbound-credentials-list-section-inject-as"
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
              value={row.inject_as_type}
              onChange={e =>
                updateRow(idx, {
                  inject_as_type: e.target.value as OutboundCredentialFormRow['inject_as_type'],
                })
              }
            >
              <option value="bearer_header">Bearer header</option>
              <option value="custom_header">Custom header</option>
              <option value="meta">JSON-RPC _meta</option>
            </Form.Select>
          </Form.Group>

          {row.inject_as_type === 'custom_header' && (
            <>
              <Form.Group className="mb-1">
                <Form.Label className="small text-muted mb-0">Header name</Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  value={row.inject_as_custom_name ?? ''}
                  onChange={e => updateRow(idx, { inject_as_custom_name: e.target.value })}
                  placeholder="X-GitHub-Token"
                />
              </Form.Group>
              <Form.Group className="mb-1">
                <Form.Label className="small text-muted mb-0">Header format</Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  value={row.inject_as_custom_format ?? ''}
                  onChange={e => updateRow(idx, { inject_as_custom_format: e.target.value })}
                  placeholder="token {value}"
                />
              </Form.Group>
            </>
          )}

          {row.inject_as_type === 'meta' && (
            <Form.Group className="mb-1">
              <Form.Label className="small text-muted mb-0">Meta field name</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                value={row.inject_as_meta_field ?? ''}
                onChange={e => updateRow(idx, { inject_as_meta_field: e.target.value })}
                placeholder="oauth_token"
              />
            </Form.Group>
          )}
        </div>
      ))}

      <Button size="sm" variant="outline-primary" onClick={addRow}>
        <i className="fas fa-plus me-1" />
        Add credential
      </Button>
    </div>
  );
};

export default OutboundCredentialsListSection;
