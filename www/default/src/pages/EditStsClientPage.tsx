import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { usePageTitle } from '../context/PageTitleContext';
import SecretSelector, { Secret } from '../components/shared/SecretSelector';
import FieldHelp from '../components/shared/FieldHelp';
import { STS_SECRET_TAG } from '../utils/secretTags';

interface SecretMeta {
  secret_id: string;
  name: string;
  secret_type?: string;
  tags?: string[];
}

const SUBJECT_TOKEN_TYPES: { urn: string; label: string; hint: string }[] = [
  {
    urn: 'urn:ietf:params:oauth:token-type:jwt',
    label: 'JWT',
    hint: 'A general-purpose signed token',
  },
  {
    urn: 'urn:ietf:params:oauth:token-type:id_token',
    label: 'ID Token',
    hint: 'Proves who a specific end user is, from a login flow',
  },
  {
    urn: 'urn:ietf:params:oauth:token-type:id-jag',
    label: 'ID-JAG',
    hint: 'A short-lived grant proving a specific identity was already verified elsewhere, without re-running that verification',
  },
  {
    urn: 'urn:affinidi:params:oauth:token-type:vp',
    label: 'Verifiable Presentation',
    hint: 'A cryptographically signed proof of identity a user or agent controls directly, not issued by a login flow',
  },
];

interface StsClientForm {
  name: string;
  client_id: string;
  client_secret_ref: string;
  allowed_audiences: string; // textarea, one per line
  allowed_scopes: string; // textarea, one per line
  allowed_subject_audiences: string; // textarea, one per line
  allowed_subject_token_types: string[];
  allow_impersonation: boolean;
  issue_id_jag: boolean;
  max_ttl_secs: string; // number as string, empty = unset
}

const EMPTY_FORM: StsClientForm = {
  name: '',
  client_id: '',
  client_secret_ref: '',
  allowed_audiences: '',
  allowed_scopes: '',
  allowed_subject_audiences: '',
  allowed_subject_token_types: [],
  allow_impersonation: false,
  issue_id_jag: false,
  max_ttl_secs: '',
};

const linesToArray = (value: string): string[] =>
  value
    .split('\n')
    .map(s => s.trim())
    .filter(s => s.length > 0);

const EditStsClientPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isNew = !id || id === 'new';
  usePageTitle(isNew ? 'New STS Client' : 'Edit STS Client');

  const [form, setForm] = useState<StsClientForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [filterStsTag, setFilterStsTag] = useState(true);

  useEffect(() => {
    if (!isNew) {
      loadClient();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    loadSecrets();
  }, []);

  const loadSecrets = async () => {
    try {
      const response = await apiClient.get('/secrets/');
      setSecrets(response.data || []);
    } catch {
      // Non-fatal: the picker just shows no options; the field is still required.
    }
  };

  const loadClient = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch(`/api/v1/sts/clients/${encodeURIComponent(id!)}`);
      if (!response.ok) {
        throw new Error(`Failed to load STS client: ${response.statusText}`);
      }
      const data = await response.json();
      setForm({
        name: data.name ?? '',
        client_id: data.client_id ?? '',
        client_secret_ref: data.client_secret_ref ?? '',
        allowed_audiences: (data.allowed_audiences ?? []).join('\n'),
        allowed_scopes: (data.allowed_scopes ?? []).join('\n'),
        allowed_subject_audiences: (data.allowed_subject_audiences ?? []).join('\n'),
        allowed_subject_token_types: data.allowed_subject_token_types ?? [],
        allow_impersonation: !!data.allow_impersonation,
        issue_id_jag: !!data.issue_id_jag,
        max_ttl_secs: data.max_ttl_secs != null ? String(data.max_ttl_secs) : '',
      });
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const toggleSubjectType = (urn: string) => {
    setForm(prev => {
      const has = prev.allowed_subject_token_types.includes(urn);
      return {
        ...prev,
        allowed_subject_token_types: has
          ? prev.allowed_subject_token_types.filter(u => u !== urn)
          : [...prev.allowed_subject_token_types, urn],
      };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError('Name is required.');
      return;
    }
    if (!form.client_id.trim()) {
      setError('Client ID is required.');
      return;
    }
    if (!form.client_secret_ref.trim()) {
      setError(
        'Client Secret Reference is required. The token endpoint has no other way to authenticate the client.'
      );
      return;
    }
    let maxTtl: number | undefined;
    if (form.max_ttl_secs.trim()) {
      const parsed = Number(form.max_ttl_secs.trim());
      if (!Number.isFinite(parsed) || parsed <= 0 || !Number.isInteger(parsed)) {
        setError('Max token TTL must be a positive whole number of seconds.');
        return;
      }
      maxTtl = parsed;
    }

    const body = {
      client_id: form.client_id.trim(),
      name: form.name.trim(),
      client_secret_ref: form.client_secret_ref.trim(),
      allowed_audiences: linesToArray(form.allowed_audiences),
      allowed_scopes: linesToArray(form.allowed_scopes),
      allowed_subject_audiences: linesToArray(form.allowed_subject_audiences),
      allowed_subject_token_types: form.allowed_subject_token_types,
      allow_impersonation: form.allow_impersonation,
      issue_id_jag: form.issue_id_jag,
      max_ttl_secs: maxTtl,
    };

    setSaving(true);
    setError(null);
    try {
      const url = isNew ? '/api/v1/sts/clients' : `/api/v1/sts/clients/${encodeURIComponent(id!)}`;
      const method = isNew ? 'POST' : 'PUT';
      const response = await apiClient.fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || response.statusText);
      }
      navigate('/credentials?tab=sts-clients');
    } catch (e: any) {
      setError(e.message ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const visibleSecrets: Secret[] = useMemo(() => {
    const base = filterStsTag
      ? secrets.filter(s => (s.tags ?? []).includes(STS_SECRET_TAG))
      : secrets;
    const mapped: Secret[] = base.map(s => ({
      id: s.secret_id,
      name: s.name,
      secret_type: s.secret_type,
    }));
    // Keep the currently-selected secret selectable even if the filter hides it.
    if (form.client_secret_ref && !mapped.some(s => s.id === form.client_secret_ref)) {
      const existing = secrets.find(s => s.secret_id === form.client_secret_ref);
      mapped.unshift({
        id: form.client_secret_ref,
        name: existing ? existing.name : `${form.client_secret_ref} (current)`,
        secret_type: existing?.secret_type,
      });
    }
    return mapped;
  }, [secrets, filterStsTag, form.client_secret_ref]);

  if (loading) {
    return (
      <div className="container-fluid text-center py-5">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => navigate('/credentials?tab=sts-clients')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-right-left me-2"></i>
            {isNew ? 'New STS Client' : 'Edit STS Client'}
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          <p className="text-muted mb-3">
            An STS client is an agent (or service) allowed to call this gateway's token-exchange
            endpoint (<code>/oauth2/token</code>) to trade a token it already has for a different
            one. For example, exchanging its own identity token for a token scoped to a specific
            downstream API. Everything below controls what this client is allowed to request and
            receive.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="name">
                Name <span className="text-danger">*</span>
              </label>
              <input
                id="name"
                name="name"
                type="text"
                className="form-control"
                value={form.name}
                onChange={handleChange}
                placeholder="e.g. Sales assistant agent"
                required
              />
              <small className="form-text text-muted">Human-readable label shown in the UI.</small>
            </div>

            <div className="mb-3">
              <label htmlFor="client_id">
                Client ID <span className="text-danger">*</span>
              </label>
              <input
                id="client_id"
                name="client_id"
                type="text"
                className="form-control font-monospace"
                value={form.client_id}
                onChange={handleChange}
                placeholder="e.g. sales-agent"
                required
              />
              <small className="form-text text-muted">
                The <code>client_id</code> the agent presents at <code>/oauth2/token</code>.
              </small>
            </div>

            <div>
              <div className="d-flex justify-content-end mb-1">
                <div className="form-check form-switch mb-0">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    role="switch"
                    id="filter-sts-secrets"
                    checked={filterStsTag}
                    onChange={e => setFilterStsTag(e.target.checked)}
                  />
                  <label className="form-check-label small text-muted" htmlFor="filter-sts-secrets">
                    Only <code>sts</code>-tagged secrets
                  </label>
                </div>
              </div>
              <SecretSelector
                secrets={visibleSecrets}
                selectedSecretId={form.client_secret_ref}
                onChange={secretId => setForm(prev => ({ ...prev, client_secret_ref: secretId }))}
                label="Client Secret Reference"
                required
                placeholder={
                  visibleSecrets.length === 0
                    ? filterStsTag
                      ? 'No STS-tagged secrets'
                      : 'No secrets available'
                    : undefined
                }
                helpText="Pick a secret_id from the Secrets store. The secret value itself is never stored on the client. This field is required: the token endpoint has no other way (such as a certificate or DID-based method) to authenticate the client, so a client without one cannot obtain tokens. Tag a secret 'sts' to have it listed here by default."
              />
            </div>

            <div className="mb-3">
              <label htmlFor="allowed_audiences">Allowed Audiences</label>
              <textarea
                id="allowed_audiences"
                name="allowed_audiences"
                className="form-control font-monospace"
                rows={3}
                value={form.allowed_audiences}
                onChange={handleChange}
                placeholder={'https://api.example.com\nhttps://reports.example.com'}
              />
              <small className="form-text text-muted">
                One audience/resource per line. Empty = any audience allowed.
              </small>
            </div>

            <div className="mb-3">
              <label htmlFor="allowed_scopes">Allowed Scopes</label>
              <textarea
                id="allowed_scopes"
                name="allowed_scopes"
                className="form-control font-monospace"
                rows={3}
                value={form.allowed_scopes}
                onChange={handleChange}
                placeholder={'reports.read\nreports.write'}
              />
              <small className="form-text text-muted">
                One scope per line. Empty = any requested scope allowed.
              </small>
            </div>

            <div className="mb-3">
              <div className="field-label-with-help">
                <label htmlFor="allowed_subject_audiences" className="mb-0">
                  Allowed Subject-Token Audiences
                </label>
                <FieldHelp
                  ariaLabel="About Allowed Subject-Token Audiences"
                  testId="field-help-subject-audiences"
                >
                  Verifiable Presentation (VP) subjects (a cryptographically signed proof of
                  identity, rather than a plain JWT) are always exempt from this check.
                </FieldHelp>
              </div>
              <textarea
                id="allowed_subject_audiences"
                name="allowed_subject_audiences"
                className="form-control font-monospace"
                rows={3}
                value={form.allowed_subject_audiences}
                onChange={handleChange}
                placeholder={'https://sts.example\nhttps://gateway.example'}
              />
              <small className="form-text text-muted">
                Optional hardening. One audience per line. When set, a JWT subject token's{' '}
                <code>aud</code> must include one of these or the exchange is rejected. Empty = no
                subject-audience check.
              </small>
            </div>

            <div className="mb-3">
              <label>Allowed Subject Token Types</label>
              <div>
                {SUBJECT_TOKEN_TYPES.map(t => (
                  <div className="form-check" key={t.urn}>
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id={`stt-${t.urn}`}
                      checked={form.allowed_subject_token_types.includes(t.urn)}
                      onChange={() => toggleSubjectType(t.urn)}
                    />
                    <label className="form-check-label" htmlFor={`stt-${t.urn}`}>
                      {t.label} <small className="text-muted">({t.hint})</small>
                    </label>
                  </div>
                ))}
              </div>
              <small className="form-text text-muted">
                Restrict which subject-token types this client may present. None selected = any
                supported type.
              </small>
            </div>

            <div className="mb-3">
              <label htmlFor="max_ttl_secs">Max Token TTL (seconds)</label>
              <input
                id="max_ttl_secs"
                name="max_ttl_secs"
                type="number"
                min={1}
                className="form-control"
                value={form.max_ttl_secs}
                onChange={handleChange}
                placeholder="e.g. 300 (leave blank for the gateway default)"
              />
              <small className="form-text text-muted">
                Caps the lifetime of tokens issued for this client (further capped by the gateway
                maximum).
              </small>
            </div>

            <div className="form-check mb-2">
              <input
                className="form-check-input"
                type="checkbox"
                id="issue_id_jag"
                checked={form.issue_id_jag}
                onChange={e => setForm(prev => ({ ...prev, issue_id_jag: e.target.checked }))}
              />
              <label className="form-check-label" htmlFor="issue_id_jag">
                <span className="field-label-with-help">
                  Allow issuing ID-JAG (<code>requested_token_type=id-jag</code>)
                  <FieldHelp
                    ariaLabel="About Allow issuing ID-JAG"
                    testId="field-help-issue-id-jag"
                  >
                    An ID-JAG (Identity Assertion Authorization Grant) is a short-lived proof that
                    identity verification already happened, meant to be handed to another service
                    rather than used directly. This setting is independent from the ID-JAG option in
                    Allowed Subject Token Types below: that one controls whether this client may
                    present an ID-JAG it already holds as input, not whether it can request a new
                    one as output.
                  </FieldHelp>
                </span>
                <small className="text-muted d-block">
                  Allow this client to request an ID-JAG as the token it receives from an exchange.
                </small>
              </label>
            </div>

            <div className="form-check mb-4">
              <input
                className="form-check-input"
                type="checkbox"
                id="allow_impersonation"
                checked={form.allow_impersonation}
                onChange={e =>
                  setForm(prev => ({ ...prev, allow_impersonation: e.target.checked }))
                }
              />
              <label className="form-check-label" htmlFor="allow_impersonation">
                <span className="field-label-with-help">
                  Allow impersonation
                  <FieldHelp
                    ariaLabel="About Allow impersonation"
                    testId="field-help-allow-impersonation"
                  >
                    This also feeds the gateway's authorization policy, not just audit logs: which
                    client is recorded as acting on whose behalf can affect whether the exchange is
                    allowed, not only how it's recorded afterward.
                  </FieldHelp>
                </span>
                <small className="text-muted d-block">
                  When off (default, recommended), an exchange that doesn't supply its own actor
                  token records this client as the delegating actor, so the issued token keeps a
                  trace of who requested it. Turn this on only if such exchanges should produce a
                  token with no trace of the original delegator (downstream systems then can't tell
                  the request was made on behalf of another identity). Exchanges that already supply
                  their own actor token are unaffected either way.
                </small>
              </label>
            </div>

            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span className="spinner-border spinner-border-sm me-2" />
                    Saving…
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-1"></i> Save
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-outline-secondary"
                onClick={() => navigate('/credentials?tab=sts-clients')}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditStsClientPage;
