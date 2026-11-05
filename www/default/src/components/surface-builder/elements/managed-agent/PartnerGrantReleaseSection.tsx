import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';

/**
 * Whether `endpoint` is a Target the gateway forwards to over HTTP or HTTPS,
 * read exactly as the gateway reads it: a lower-case `http://` or `https://`
 * with nothing before it.
 */
export function isHttpTarget(endpoint: unknown): boolean {
  return typeof endpoint === 'string' && /^https?:\/\//.test(endpoint);
}

interface PartnerGrantReleaseSectionProps {
  checked: boolean;
  onChange: (next: boolean) => void;
}

const PartnerGrantReleaseSection: React.FC<PartnerGrantReleaseSectionProps> = ({
  checked,
  onChange,
}) => (
  <div className="config-section">
    <label>Fabric Callers</label>
    <Form.Check
      type="switch"
      id="managed-agent-partner-grants"
      data-testid="managed-agent-partner-grants-switch"
      label={
        <span className="d-flex align-items-center gap-1">
          Release per-user grants to Fabric callers
          <FieldHelp
            testId="field-help-managed-agent-partner-grants"
            ariaLabel="About Release per-user grants to Fabric callers"
          >
            <p>
              When this is on, a request a paired gateway sends over Fabric gets the delegated
              credential of the person whose own token it carries, from the surface&apos;s
              Credential Delegation bindings, once that person has connected by calling this surface
              directly. Consent is never started through the paired gateway.
            </p>
            <p>
              For legacy requests, each person then has one grant for this surface, whichever agent
              acts for them, and a person who connected through a particular agent before connects
              once more. A grant made through a 2026-07-28 MCP request stays with the agent that
              asked for it and never reaches a paired gateway&apos;s requests.
            </p>
            <p>
              It applies only while the surface&apos;s Caller Context tells people apart: a JWT
              Bearer method that names an audience, or resource tokens. With an API key, API Key
              Provider or DID Auth method nothing is released, and saving warns.
            </p>
            <p>
              Two Agent Gateways cannot use this yet, and never turn it on for a paired gateway that
              sends one fixed JWT for all its users: every one of them would get the grant of
              whoever connected with that token.
            </p>
          </FieldHelp>
        </span>
      }
      checked={checked}
      onChange={e => onChange(e.target.checked)}
    />
    {checked && (
      <Form.Text
        className="d-block text-warning"
        style={{ fontSize: '10px' }}
        data-testid="managed-agent-partner-grants-warning"
      >
        <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />A paired gateway that
        sends a person&apos;s own token gets that person&apos;s grant. Tell your users before you
        save.
      </Form.Text>
    )}
  </div>
);

export default PartnerGrantReleaseSection;
