import React from 'react';
import { Form } from 'react-bootstrap';
import type { CanvasNode } from '../../SurfaceCanvas';
import FieldHelp from '../../../shared/FieldHelp';

export function hasOutboundCredentialBindings(allNodes: CanvasNode[] | undefined): boolean {
  return (allNodes ?? []).some(
    node =>
      node.type === 'credential-delegation' &&
      Array.isArray(node.config?.outbound_credentials_form) &&
      node.config.outbound_credentials_form.some(
        (row: { credential_provider_id?: string }) => !!row?.credential_provider_id
      )
  );
}

export function fabricPeerGatewayId(endpoint: unknown, fallback?: string): string | undefined {
  if (typeof endpoint === 'string' && endpoint.startsWith('fabric://')) {
    const gatewayId = endpoint.slice('fabric://'.length).split('/')[0];
    if (gatewayId) return gatewayId;
  }
  return fallback || undefined;
}

interface FabricDelegatedCredentialsSectionProps {
  /** Prefix for the switch id and test ids, e.g. `managed-agent` or `transit-point`. */
  testIdPrefix: string;
  /** Distinguishes several instances on one page, such as one per Transit Point. */
  instanceKey?: string;
  checked: boolean;
  peerName?: string;
  onChange: (next: boolean) => void;
}

const FabricDelegatedCredentialsSection: React.FC<FabricDelegatedCredentialsSectionProps> = ({
  testIdPrefix,
  instanceKey,
  checked,
  peerName,
  onChange,
}) => {
  const id = `${testIdPrefix}-fabric-delegated-credentials${instanceKey ? `-${instanceKey}` : ''}`;
  return (
    <div className="config-section">
      <label>Delegated Credentials</label>
      <Form.Check
        type="switch"
        id={id}
        data-testid={`${testIdPrefix}-fabric-delegated-credentials-switch`}
        label={
          <span className="d-flex align-items-center gap-1">
            Send delegated credentials over Fabric
            <FieldHelp
              testId={`field-help-${testIdPrefix}-fabric-delegated-credentials`}
              ariaLabel="About Send delegated credentials over Fabric"
            >
              <p>
                When this is on, the caller&apos;s delegated access token is sent to the remote
                gateway with each request on this route. It comes from the surface&apos;s Credential
                Delegation bindings or, for a Transit Point without those, from its own transit
                credentials. The refresh token never leaves this gateway.
              </p>
              <p>
                When it is off, the remote gateway receives no delegated credential. The
                caller&apos;s own token is always removed before the request crosses Fabric.
              </p>
              <p>
                Modern (2026-07-28) MCP requests through the Access Point carry the token. A Transit
                Point carries it on both modern and legacy requests.
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
          data-testid={`${testIdPrefix}-fabric-delegated-credentials-warning`}
        >
          <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
          The caller&apos;s access token is sent to {peerName || 'the remote gateway'}. Turn this on
          only for peers you trust with it.
        </Form.Text>
      )}
    </div>
  );
};

export default FabricDelegatedCredentialsSection;
