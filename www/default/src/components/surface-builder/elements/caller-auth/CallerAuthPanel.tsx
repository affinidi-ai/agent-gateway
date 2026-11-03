import React from 'react';
import { Form } from 'react-bootstrap';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { discoverySaveError, readProtectedResource } from './protectedResource';
import { readMethods } from './methods';
import CallerAuthMethodList from './CallerAuthMethodList';
import { selectMethod } from './selectedMethod';

/**
 * Compact sidebar panel for the Caller Auth element: its methods, one row
 * each, and the authorization server discovery status. Configure on a row
 * opens that method's settings in the fullscreen editor.
 */
const CallerAuthPanel: React.FC<ConfigPanelProps> = ({
  node,
  config,
  updateFields,
  protocol,
  openFullscreenEditor,
}) => {
  const meta = useOptionalSurfaceMeta();
  const discovery = readProtectedResource(config.protected_resource);
  const showsDiscovery = protocol === 'mcp' && readMethods(config)[0]?.method_type === 'jwt_bearer';
  const configure = (position: number) => {
    selectMethod(node.id, position);
    openFullscreenEditor?.();
  };
  const discoveryError = showsDiscovery
    ? discoverySaveError(meta?.saveError, discovery?.resource)
    : null;

  return (
    <>
      <Form.Text className="text-muted d-block mb-1" style={{ fontSize: '10px' }}>
        Extracts and verifies the caller&apos;s identity before any policy or payment gate runs. A
        closed Access Point (Public access off) is not ready for external access without it, and
        answers every caller with <code>503</code>. Once it is ready, a missing or invalid
        credential is refused with <code>401</code>. On a public Access Point, or one without the
        Public access setting, the request continues to policy as{' '}
        <code>source_auth.method == &quot;failed&quot;</code>.
      </Form.Text>
      <InfoBanner
        title="Why does this matter to the rest of the pipeline?"
        icon="fa-circle-info"
        summary={
          <>
            <p>
              This exposes the caller&apos;s context to the rest of the pipeline: used by OPA
              policies (<code>input.source_auth</code>) and by workload binding to populate{' '}
              <code>userIdentity</code> in the outbound / response VP (Verifiable Presentation, a
              signed identity document).
            </p>
            <p>
              Without this, downstream stages only see the agent identity, not the human (or
              service) on whose behalf the call is being made.
            </p>
          </>
        }
      />

      <div className="config-section">
        <label>Authentication methods</label>
        <CallerAuthMethodList
          config={config}
          updateFields={updateFields}
          onConfigure={configure}
          area="caller-auth-panel"
        />
        <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '10px' }}>
          Each caller is verified by the method its credential belongs to; a caller presenting
          credentials for more than one is refused. Default: JWT Bearer, the standard choice unless
          you specifically need an API key or client certificate.
        </Form.Text>
        {showsDiscovery && (
          <Form.Text
            className="text-muted d-block mt-2"
            style={{ fontSize: '10px' }}
            data-testid="caller-auth-panel-discovery-status"
          >
            Authorization server discovery:{' '}
            {discovery ? (
              <strong>
                on, {discovery.authorization_servers.length} authorization server
                {discovery.authorization_servers.length === 1 ? '' : 's'}
              </strong>
            ) : (
              <strong>off</strong>
            )}
          </Form.Text>
        )}
        {discoveryError && (
          <div
            className="invalid-feedback d-block"
            style={{ fontSize: '10px' }}
            data-testid="caller-auth-panel-discovery-save-error"
          >
            {discoveryError}
          </div>
        )}
      </div>
    </>
  );
};

export default CallerAuthPanel;
