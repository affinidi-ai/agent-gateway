import React from 'react';
import FieldHelp from '../../components/shared/FieldHelp';

interface AuditInfoBannerProps {
  open: boolean;
  onToggle: () => void;
}

/** Collapsible "About the Audit Log" explainer (collapsed by default). */
const AuditInfoBanner: React.FC<AuditInfoBannerProps> = ({ open, onToggle }) => (
  <div className="alert alert-info mb-3" role="note">
    <button
      type="button"
      className="btn btn-link p-0 text-decoration-none d-flex align-items-center w-100 text-start text-reset"
      onClick={onToggle}
      aria-expanded={open}
      data-testid="audit-about-toggle"
    >
      <i className="fas fa-info-circle me-2" />
      <span className="fw-semibold">About the Audit Log</span>
      <i className={`fas fa-chevron-${open ? 'up' : 'down'} ms-auto`} aria-hidden="true" />
    </button>
    {open && (
      <div className="small mt-2" data-testid="audit-about-body">
        <p className="mb-2">
          This tamper-evident log records the decisions that governed proxied requests: every
          gateway, surface, MCP-tool and response OPA
          <FieldHelp testId="field-help-audit-opa" ariaLabel="About OPA">
            OPA (Open Policy Agent) is the engine that evaluates this gateway's policies.
          </FieldHelp>{' '}
          policy allow/deny, TRQP
          <FieldHelp testId="field-help-audit-trqp" ariaLabel="About TRQP">
            TRQP (Trust Registry Query Protocol) is how this gateway asks a connected Trust Registry
            whether a caller or target agent is recognised.
          </FieldHelp>{' '}
          trust-check outcome, and Verifiable Presentation injected on behalf of the calling agent.
          Each entry is embedded in the signed VP, so its <code>policyDecisions</code> are
          cryptographically attested. Entries appear only when a request actually exercises the
          pipeline, and only while VP Auditing is enabled in Settings › Security.
        </p>
        <p className="mb-2">
          To send every entry to Kafka, Kinesis, Pulsar, Redis Streams or a webhook as it is
          written, add an integration in the <strong>Governance Audit</strong> category. Forwarding
          is best-effort; this log stays the record of truth.
        </p>
        <p className="mb-1 fw-semibold">Categories</p>
        <ul className="mb-0 ps-3">
          <li>
            <strong>Policy Decisions</strong> (<code>policy_decision</code>): a gateway, surface,
            MCP-tool or response OPA policy allowed or denied the request; the decision is attested
            in the signed VP&rsquo;s <code>policyDecisions</code>.
          </li>
          <li>
            <strong>Trust Checks</strong> (<code>trust_check</code>): a per-leg TRQP
            recognition/authorization query outcome exposed to OPA at{' '}
            <code>trust_check_results</code>.
          </li>
          <li>
            <strong>Trace Terminated</strong> (<code>trace_terminated</code>): this surface
            terminated the end-to-end trace at its egress; it kept its own trace and forwarded a
            fresh one downstream. The entry records the <code>own → downstream</code> mapping so the
            terminated trace can be bridged without the incoming trace crossing the boundary.
          </li>
          <li>
            <strong>VP Injected</strong> (<code>vp_injected</code>): a Verifiable Presentation
            carrying the agent&rsquo;s identity was injected into the proxied request or response.
          </li>
          <li>
            <strong>Token Injected</strong> (<code>token_injected</code>): a delegated credential
            from the vault was injected on the caller&rsquo;s behalf.
          </li>
          <li>
            <strong>Consent Granted</strong> (<code>consent_granted</code>): a user completed the
            OAuth consent flow and a delegation token was stored.
          </li>
        </ul>

        <p className="mb-1 mt-2 fw-semibold">Policy decision markers</p>
        <p className="mb-1">
          Each policy decision carries a <strong>Type</strong> (which OPA policy evaluated) and a{' '}
          <strong>Flow</strong> (which direction of traffic it governed). Use the filter row to
          narrow by decision, flow, or type.
        </p>
        <ul className="mb-2 ps-3">
          <li>
            <i className="fas fa-shield-alt me-1" aria-hidden="true" />
            <strong>Gateway</strong>: the gateway-wide OPA policy (evaluated before surface policy;
            a gateway deny is final).
          </li>
          <li>
            <i className="fas fa-exchange-alt me-1" aria-hidden="true" />
            <strong>Surface</strong>: the per-surface (channel) OPA policy.
          </li>
          <li>
            <i className="fas fa-tools me-1" aria-hidden="true" />
            <strong>MCP Tool</strong>: a per-tool policy on an MCP surface.
          </li>
          <li>
            <i className="fas fa-reply me-1" aria-hidden="true" />
            <strong>Response</strong>: a policy evaluated on the upstream response before it is
            returned.
          </li>
        </ul>
        <ul className="mb-0 ps-3">
          <li>
            <i className="fas fa-sign-in-alt me-1" aria-hidden="true" />
            <strong>Access Point</strong>: an inbound request arriving at the surface&rsquo;s access
            point (ingress).
          </li>
          <li>
            <i className="fas fa-sign-out-alt me-1" aria-hidden="true" />
            <strong>Transit Point</strong>: an outbound request the managed agent sends through a
            transit point (egress).
          </li>
          <li>
            <i className="fas fa-network-wired me-1" aria-hidden="true" />
            <strong>Fabric</strong>: a request received over the fabric (gateway-to-gateway) at a
            connection point.
          </li>
        </ul>
      </div>
    )}
  </div>
);

export default AuditInfoBanner;
