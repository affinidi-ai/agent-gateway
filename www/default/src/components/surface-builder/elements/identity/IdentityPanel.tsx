import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { useApp } from '../../../../context/AppContext';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { CertificateKind } from '../../../../types';
import { deepLinks } from '../../../../utils/deepLinks';
import { HEADER_METADATA_EXTENSION_URI } from '../_shared/headerMetadataMapping';
import { transitPointProtocol } from '../transit-point/TransitPointPanel';
import FieldHelp from '../../../shared/FieldHelp';

interface ApiKeyOption {
  key_id: string;
  agent_id: string;
  client_id: string;
  status: 'active' | 'revoked';
}

interface CertificateOption {
  id: string;
  name: string;
  active: boolean;
  kind?: CertificateKind;
}

type ExtractionType =
  | ''
  | 'from_payload'
  | 'from_api_key'
  | 'from_mtls'
  | 'static'
  | 'from_jwt_claim';

type ExtractionTypeOption = {
  value: Exclude<ExtractionType, ''>;
  label: string;
  disabled?: boolean;
};

const TYPE_OPTIONS: ExtractionTypeOption[] = [
  { value: 'from_payload', label: 'From Payload (identity metadata)' },
  { value: 'from_api_key', label: 'From API Key' },
  { value: 'from_jwt_claim', label: 'From JWT Claims' },
  { value: 'static', label: 'Static DID', disabled: true },
  { value: 'from_mtls', label: 'From mTLS certificate', disabled: true },
];

const typeOptionsForPlacement = (isTransitPointIdentity: boolean): ExtractionTypeOption[] =>
  TYPE_OPTIONS.map(option => ({
    ...option,
    disabled:
      option.disabled || (isTransitPointIdentity && option.value !== 'from_payload') || undefined,
  }));

const isSelectableExtractionType = (
  value: ExtractionType,
  options: ExtractionTypeOption[]
): value is Exclude<ExtractionType, ''> =>
  value !== '' && !options.some(option => option.value === value && option.disabled);

/**
 * Per-slot context blurb shown at the top of the panel. The same
 * Agent Identity element can sit in four distinct slots; each one
 * resolves a different concept and writes to a different backend
 * field. Surface the role explicitly so the user isn't left guessing
 * which identity they're configuring.
 */
interface SlotContext {
  title: string;
  /** One-line role summary. */
  summary: string;
  /** Which canvas arrow this slot belongs to. */
  where: string;
  /** When you'd actually use this slot. */
  when: string;
  /** Concrete example to disambiguate from the other identity slots. */
  example: string;
}

function describeIdentitySlot(slotId?: string): SlotContext | null {
  switch (slotId) {
    case 'request:identity-inbound':
      return {
        title: 'Inbound caller identity',
        summary: 'WHO is calling the gateway from outside.',
        where: 'Caller → Managed Agent (request leg).',
        when: 'Whenever you need the caller’s DID for policy, trust-registry checks, audit, or to forward as agent context to downstream hops.',
        example:
          'A peer agent calls your gateway. Extract their DID from the incoming identity payload so OPA can check the trust registry before the request reaches your MA.',
      };
    case 'response:identity-protected':
      return {
        title: 'Protected (Managed) Agent identity',
        summary: 'WHO YOUR agent is: the agent behind the gateway.',
        where: 'Managed Agent → Caller (response leg).',
        when: 'When your MA itself publishes its DID in its replies and the gateway needs to capture it for outgoing mirror / trust-registry / VP flows so callers can verify which agent answered.',
        example:
          'Configure the fields your MA emits as identity evidence in its response so the gateway can derive and present the MA DID to callers.',
      };
    case 'response:identity-external':
      return {
        title: 'External (upstream) Agent identity',
        summary: 'WHO your Managed Agent is talking to upstream.',
        where: 'External Target → Managed Agent (response leg).',
        when: 'When your MA acts as a relay/aggregator and you need to record the upstream agent’s DID (for metrics, downstream policy, mirror enrichment). Replaced by the per-Transit-Point slot when Transit Points exist.',
        example:
          'Your MA calls a third-party A2A agent and proxies its answer back. Extract that upstream agent’s identity payload so audit logs show both your MA AND the upstream it consulted.',
      };
    case 'request:identity-managed_identity':
    case 'response:identity-managed_identity':
      return {
        title: 'Outbound managed-agent identity',
        summary: 'WHO the managed agent is on calls it initiates through this Transit Point.',
        where: 'Managed Agent → Transit Point request leg, this TP only.',
        when: 'When the managed agent can present identity material only on requests to this Transit Point, such as headers normalized by Header Metadata Mapping.',
        example:
          'Copilot Studio calls this TP with Entra agent and tenant headers. Map those headers into A2A metadata, then read that metadata here to derive the managed agent DID before the request is forwarded.',
      };
    default:
      return null;
  }
}

/**
 * Common scenario: Protected AND External together.
 * --------------------------------------------------
 * When your MA is a relay (caller → MA → upstream agent → MA → caller),
 * both slots make sense on the SAME surface:
 *
 *   - Protected = WHO answered the caller (your MA's DID).
 *   - External  = WHO your MA consulted upstream (the third-party DID).
 *
 * Use both when audit/compliance needs to record the full chain of
 * agent identities involved in producing the response.
 */

/**
 * Compact sidebar panel for the Agent Identity element. Heavy editors
 * (payload field list, JSON editors) are delegated to the per-element
 * `FullscreenPanel` via `openFullscreenEditor()`.
 */
const IdentityPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateField,
  protocol,
  openFullscreenEditor,
  allNodes,
}) => {
  // No default extraction type — user must explicitly pick one.
  const extractionType: ExtractionType = (config.type as ExtractionType) || '';
  const slotContext = describeIdentitySlot(node.slotId);
  const [apiKeys, setApiKeys] = useState<ApiKeyOption[]>([]);
  const [certificates, setCertificates] = useState<CertificateOption[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [loadingCerts, setLoadingCerts] = useState(false);

  useEffect(() => {
    if (extractionType !== 'from_api_key' || apiKeys.length > 0) return;
    setLoadingKeys(true);
    apiClient
      .fetch('/api/v1/api-keys')
      .then(r => (r.ok ? r.json() : []))
      .then((data: ApiKeyOption[]) => setApiKeys(data.filter(k => k.status === 'active')))
      .catch(() => setApiKeys([]))
      .finally(() => setLoadingKeys(false));
  }, [extractionType, apiKeys.length]);

  useEffect(() => {
    if (extractionType !== 'from_mtls' || certificates.length > 0) return;
    setLoadingCerts(true);
    apiClient
      .fetch('/api/v1/certificates/')
      .then(r => (r.ok ? r.json() : []))
      .then((data: CertificateOption[]) =>
        // Identity injection needs a client leaf cert (the cert that
        // identifies the upstream agent). Filter out server certs and
        // CAs; treat unkinded legacy entries as client leaves.
        setCertificates(data.filter(c => c.active && (c.kind ?? 'client_leaf') === 'client_leaf'))
      )
      .catch(() => setCertificates([]))
      .finally(() => setLoadingCerts(false));
  }, [extractionType, certificates.length]);

  const fieldCount = Array.isArray(config.fields) ? config.fields.length : 0;
  const parentTransitProtocol = transitPointProtocol(
    allNodes?.find(candidate => candidate.id === node.parentId)?.type
  );
  const identityProtocol = parentTransitProtocol ?? protocol;
  const isA2aLikeProtocol = identityProtocol === 'a2a' || identityProtocol === 'ap2';
  const isTransitPointIdentity = parentTransitProtocol !== null;
  const extractionTypeOptions = typeOptionsForPlacement(isTransitPointIdentity);
  const isInboundA2aIdentity =
    node.slotId === 'request:identity-inbound' && (protocol === 'a2a' || protocol === 'ap2');
  const isTransitPointA2aIdentity =
    (node.slotId === 'request:identity-managed_identity' ||
      node.slotId === 'response:identity-managed_identity') &&
    (parentTransitProtocol === 'a2a' || parentTransitProtocol === 'ap2');
  const canUseHeaderMetadata =
    extractionType === 'from_payload' && (isInboundA2aIdentity || isTransitPointA2aIdentity);

  return (
    <>
      {slotContext && (
        <InfoBanner title={slotContext.title} icon="fa-id-badge" collapsible={false}>
          <div className="surface-info-panel-summary">{slotContext.summary}</div>
          <InfoBanner title="Where / When / Example" icon="fa-list">
            <dl>
              <dt>Where</dt>
              <dd>{slotContext.where}</dd>
              <dt>When</dt>
              <dd>{slotContext.when}</dd>
              <dt>Example</dt>
              <dd style={{ fontStyle: 'italic' }}>{slotContext.example}</dd>
            </dl>
          </InfoBanner>
        </InfoBanner>
      )}
      <div className="config-section">
        <label htmlFor={`identity-extraction-type-${node.id}`}>Identity Extraction Type</label>
        <Form.Select
          id={`identity-extraction-type-${node.id}`}
          size="sm"
          className="dropdown-styling"
          value={extractionType}
          onChange={e => {
            const nextType = e.target.value as ExtractionType;
            if (nextType === '' || isSelectableExtractionType(nextType, extractionTypeOptions)) {
              updateField('type', nextType);
            }
          }}
        >
          <option value="">Select an identity extraction type…</option>
          {extractionTypeOptions.map(opt => (
            <option key={opt.value} value={opt.value} disabled={opt.disabled}>
              {opt.label}
            </option>
          ))}
        </Form.Select>
        <Form.Text className="text-muted d-block" style={{ fontSize: '10px' }}>
          <div>Choose how the gateway identifies the caller or agent on this leg.</div>
          <ul className="mb-0 ps-3">
            <li>
              <strong>From Payload</strong>: identity details are already in the request or response
              body (most common).
            </li>
            <li>
              <strong>From API Key</strong>: the caller authenticates with an API key you&apos;ve
              issued.
            </li>
            <li>
              <strong>From JWT Claims</strong>: the caller sends a signed token; read the identity
              from one of its fields.
            </li>
            <li>
              <strong>Static DID</strong> and <strong>From mTLS certificate</strong> can&apos;t be
              selected here.
            </li>
          </ul>
        </Form.Text>
      </div>

      {extractionType === 'from_payload' && (
        <>
          {canUseHeaderMetadata && (
            <div className="config-section">
              <label>A2A Identity Source</label>
              <Form.Group className="mb-2">
                <Form.Label className="small text-muted mb-1">Metadata extension URI</Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  placeholder="https://fabric.affinidi.io/extensions/agent-identity/v1"
                  value={config.extension_uri || ''}
                  onChange={e => updateField('extension_uri', e.target.value)}
                />
                <Form.Text className="d-block text-muted" style={{ fontSize: '11px' }}>
                  Leave blank to read the standard Affinidi agent identity extension. Use Header
                  Metadata Mapping when mapped header metadata carries identity fields for this
                  slot.
                </Form.Text>
              </Form.Group>
              <button
                type="button"
                className="btn btn-outline-primary btn-sm w-100 mb-2"
                data-testid="identity-read-from-header-metadata"
                onClick={() => updateField('extension_uri', HEADER_METADATA_EXTENSION_URI)}
              >
                <i className="fas fa-link me-1" /> Read from Header Metadata Mapping
              </button>
            </div>
          )}
          <div className="config-section">
            <label className="d-flex justify-content-between align-items-center">
              <span className="d-flex align-items-center gap-1">
                Payload Fields
                <FieldHelp
                  testId="field-help-identity-payload-fields"
                  ariaLabel="About Payload Fields"
                >
                  Dot-notation paths concatenated and hashed to derive the agent's DID: its
                  Decentralized Identifier, a unique ID string (e.g.{' '}
                  <code>did:web:example.com:agent:sales-bot</code>) that stands in for "who this
                  agent is" everywhere else in the gateway.
                </FieldHelp>
              </span>
              <span className="badge text-bg-secondary">{fieldCount}</span>
            </label>
            <button
              className="btn btn-outline-primary btn-sm w-100"
              onClick={() => openFullscreenEditor?.()}
              disabled={!openFullscreenEditor}
            >
              <i className="fas fa-pen-to-square me-1" /> Configure Fields…
            </button>
          </div>
          {!isA2aLikeProtocol && (
            <div className="config-section">
              <Form.Check
                type="checkbox"
                id={`strip-raw-meta-${node.id}`}
                label={
                  <span className="d-flex align-items-center gap-1">
                    Strip raw identity metadata after injection
                    <FieldHelp
                      testId="field-help-identity-strip-raw-identity-metadata-after-injection"
                      ariaLabel="About Strip raw identity metadata after injection"
                    >
                      When on, the raw <code>_meta.[field]</code> values are deleted once the
                      gateway has packaged them into a VP (Verifiable Presentation, a signed,
                      tamper-proof identity document). Turn this on to avoid forwarding duplicate,
                      unsigned copies of identity data downstream.
                    </FieldHelp>
                  </span>
                }
                checked={!!config.strip_raw_meta}
                onChange={e => updateField('strip_raw_meta', e.target.checked)}
              />
            </div>
          )}
        </>
      )}

      {extractionType === 'from_api_key' && (
        <div className="config-section">
          <label>API Key</label>
          <Form.Select
            size="sm"
            className="dropdown-styling"
            value={config.api_key_id || ''}
            onChange={e => updateField('api_key_id', e.target.value)}
            disabled={loadingKeys}
          >
            <option value="">{loadingKeys ? 'Loading…' : 'Select an API key'}</option>
            {apiKeys.map(k => (
              <option key={k.key_id} value={k.key_id}>
                {k.client_id} — {k.agent_id}
              </option>
            ))}
          </Form.Select>
          {!loadingKeys && (
            <Form.Text className="text-muted">
              {apiKeys.length === 0 ? 'No active API keys yet. ' : "Don't see the one you need? "}
              <AddResourceLink to={deepLinks.apiKey} testid="identity-panel-add-api-key-link">
                Add API key
              </AddResourceLink>
            </Form.Text>
          )}
        </div>
      )}

      {extractionType === 'from_mtls' && (
        <div className="config-section">
          <label>Client Certificate</label>
          <Form.Select
            size="sm"
            className="dropdown-styling"
            value={config.certificate_id || ''}
            onChange={e => updateField('certificate_id', e.target.value)}
            disabled={loadingCerts}
          >
            <option value="">{loadingCerts ? 'Loading…' : 'Select a certificate'}</option>
            {certificates.map(c => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </Form.Select>
          {!loadingCerts && (
            <Form.Text className="text-muted">
              {certificates.length === 0
                ? 'No active client-leaf certificates yet. '
                : "Don't see the one you need? "}
              <AddResourceLink
                to={deepLinks.certificate('client_leaf')}
                testid="identity-panel-add-certificate-link"
              >
                Add certificate
              </AddResourceLink>
            </Form.Text>
          )}
        </div>
      )}

      {extractionType === 'static' && (
        <div className="config-section">
          <label>Static DID</label>
          <Form.Control
            size="sm"
            type="text"
            placeholder="did:web:example.com:agent:my-agent"
            value={config.static_did || ''}
            onChange={e => updateField('static_did', e.target.value)}
          />
        </div>
      )}

      {extractionType === 'from_jwt_claim' && (
        <div className="config-section">
          <label>JWT Claim</label>
          <Form.Control
            size="sm"
            type="text"
            placeholder="oid"
            value={config.claim ?? ''}
            onChange={e => updateField('claim', e.target.value)}
          />
          <Form.Text className="d-block text-muted mb-2" style={{ fontSize: '11px' }}>
            Requires JWT Bearer caller authentication on this surface.
          </Form.Text>
          <label className="d-flex align-items-center gap-1">
            Namespace Claims
            <FieldHelp
              testId="field-help-identity-namespace-claims"
              ariaLabel="About Namespace Claims"
            >
              Extra fields from the caller's JWT token (such as <code>iss</code> for who issued it,
              or <code>tid</code> for tenant ID) added alongside the JWT Claim value when building
              the agent's DID. Use this when the same claim value could show up for different
              tenants or token issuers.
            </FieldHelp>
          </label>
          <Form.Control
            size="sm"
            type="text"
            placeholder="iss, tid"
            value={(Array.isArray(config.namespace_claims) ? config.namespace_claims : []).join(
              ', '
            )}
            onChange={e =>
              updateField(
                'namespace_claims',
                e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(Boolean)
              )
            }
          />
        </div>
      )}
    </>
  );
};

export default IdentityPanel;
