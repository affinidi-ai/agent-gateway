import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import { ROUTES, trustAgentResumePath } from '../routes';
import { showToast } from '../utils/toaster';
import { VtaConnectionsList } from './VtaConnectionsPage/VtaConnectionsList';
import { ControlKeyCard } from './VtaConnectionsPage/ControlKeyCard';
import { StrandedAgentsError, useVtaConnections } from './VtaConnectionsPage/useVtaConnections';
import type { VtaConnection } from './VtaConnectionsPage/types';

/** What connecting a Verifiable Trust Agent gives, shown at the top of the tab. */
const INTRO =
  "Connect a Verifiable Trust Agent to sign audit records with a key the gateway doesn't hold. A compromised gateway can't take the signing key with it, and its access can be revoked from the trust agent. You keep full control of the agent.";

/** Which DID the contexts this gateway creates sign as, set by the deployment's configuration. */
const contextDidNote = (method: string | undefined, hosting: string | undefined): string | null => {
  if (method === 'did_webvh') {
    const where =
      hosting === 'vta_server' ? "on the trust agent's webvh server" : 'by this gateway';
    return `New contexts sign as a did:webvh, hosted ${where}. The trust agent's operator can rotate a context's key without changing its DID.`;
  }
  if (method === 'did_key') {
    return "New contexts sign as a did:key: the context's key itself, with nothing to host. Rotating that key changes the DID.";
  }
  return null;
};

interface TrustAgentsPageProps {
  /** The Connections page's shared filter; the tab then shows no filter of its own. */
  externalSearchTerm?: string;
  onCountChange?: (filtered: number, total: number) => void;
  /** The Connections tab banner, where the Connect button is rendered. */
  actionsContainer?: HTMLElement | null;
}

/**
 * The Verifiable Trust Agent tab of Connections — the agents this gateway
 * can sign through, and what state each connection's pairing is in.
 */
const TrustAgentsPage: React.FC<TrustAgentsPageProps> = ({
  externalSearchTerm,
  onCountChange,
  actionsContainer,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const {
    connections,
    deployment,
    loading,
    error,
    reload,
    refresh,
    rotateControlKey,
    cancelControlKeyRotation,
    verify,
    revoke,
  } = useVtaConnections();
  const search = externalSearchTerm ?? '';
  const isEmbedded = externalSearchTerm !== undefined;
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [strandedConfirm, setStrandedConfirm] = useState<string | null>(null);

  const contextDid = contextDidNote(
    deployment?.context_did_method,
    deployment?.context_did_hosting
  );
  const canEdit = hasPermission('vta_connections.edit');
  const canRotateKeys = hasPermission('key_management.edit');
  const canDelete = hasPermission('vta_connections.delete');

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return connections;
    return connections.filter(
      c =>
        c.name.toLowerCase().includes(needle) ||
        c.vta_did.toLowerCase().includes(needle) ||
        c.endpoint.toLowerCase().includes(needle)
    );
  }, [connections, search]);

  const anyRotating = connections.some(c => Boolean(c.control_key_state?.rotation));
  useEffect(() => {
    if (!anyRotating) return undefined;
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [anyRotating, refresh]);

  const handleRotateKey = useCallback(
    async (connection: VtaConnection) => {
      setBusyId(connection.id);
      try {
        const outcome = await rotateControlKey(connection);
        showToast(
          'success',
          outcome === 'finished'
            ? `${connection.name}: control key rotated. Its DID did not change.`
            : `${connection.name}: control key rotation is under way.`
        );
      } catch (e) {
        showToast(
          'error',
          e instanceof Error ? e.message : 'The control key could not be rotated.'
        );
      } finally {
        setBusyId(null);
      }
    },
    [rotateControlKey]
  );

  const handleCancelRotation = useCallback(
    async (connection: VtaConnection) => {
      setBusyId(connection.id);
      try {
        await cancelControlKeyRotation(connection);
        showToast('success', `${connection.name}: rotation cancelled. The previous key is in use.`);
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'The rotation could not be cancelled.');
      } finally {
        setBusyId(null);
      }
    },
    [cancelControlKeyRotation]
  );

  const handleVerify = useCallback(
    async (connection: VtaConnection) => {
      setBusyId(connection.id);
      try {
        await verify(connection);
        showToast('success', `${connection.name} is connected.`);
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'Verification failed.');
      } finally {
        setBusyId(null);
      }
    },
    [verify]
  );

  const handleRevoke = useCallback(
    async (connection: VtaConnection) => {
      // Two-step: the first click arms, the second commits — the shared
      // destructive pattern, because revoking stops every surface mapped to
      // this connection from signing immediately.
      if (confirmRevoke !== connection.id) {
        setConfirmRevoke(connection.id);
        showToast('error', `Click Revoke again to stop ${connection.name} signing.`);
        return;
      }
      setConfirmRevoke(null);
      setBusyId(connection.id);
      try {
        await revoke(connection, strandedConfirm === connection.id);
        setStrandedConfirm(null);
        showToast('success', `${connection.name} is revoked and can no longer sign.`);
      } catch (e) {
        if (e instanceof StrandedAgentsError) {
          setStrandedConfirm(connection.id);
          setConfirmRevoke(connection.id);
          showToast('error', `${e.message} Click Revoke again to proceed.`);
        } else {
          showToast('error', e instanceof Error ? e.message : 'Revoke failed.');
        }
      } finally {
        setBusyId(null);
      }
    },
    [confirmRevoke, strandedConfirm, revoke]
  );

  useEffect(() => {
    onCountChange?.(filtered.length, connections.length);
  }, [filtered.length, connections.length, onCountChange]);

  const connectButton = canEdit ? (
    <AppButton
      variant="primary"
      size="sm"
      data-testid="trust-agents-connect-button"
      onClick={() => navigate(ROUTES.TRUST_AGENT_CONNECT)}
      iconStart={<i className="fas fa-plus me-1" aria-hidden="true" />}
    >
      Add VTA
    </AppButton>
  ) : null;

  return (
    <div className={isEmbedded ? '' : 'container-fluid'} data-testid="page-trust-agents">
      {actionsContainer && connectButton && createPortal(connectButton, actionsContainer)}

      <p className="text-muted mb-2" data-testid="trust-agents-intro">
        {INTRO}
      </p>
      {contextDid && (
        <p className="small text-muted mb-4" data-testid="trust-agents-context-did">
          <i className="fas fa-fingerprint me-1" aria-hidden="true" />
          {contextDid}
        </p>
      )}

      {deployment?.control_key && (
        <ControlKeyCard
          controlKey={deployment.control_key}
          canRotate={canRotateKeys}
          onRotated={reload}
        />
      )}

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-robot me-2" aria-hidden="true" />
            Verifiable Trust Agents
            <Badge
              value={filtered.length}
              suffix={search ? ` of ${connections.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length} VTA connections`}
            />
          </h6>
          <div className="d-flex align-items-center gap-2">
            {!actionsContainer && connectButton}
            <AppButton variant="outline-secondary" size="sm" onClick={() => void reload()}>
              Refresh
            </AppButton>
          </div>
        </div>

        <div className="card-body">
          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && !loading && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
              {error}
              <AppButton
                variant="outline-danger"
                size="sm"
                className="ms-3"
                onClick={() => void reload()}
              >
                Retry
              </AppButton>
            </div>
          )}

          {!loading && !error && connections.length === 0 && (
            <EmptyState
              icon="fa-robot"
              title="No Verifiable Trust Agent connected"
              body={INTRO}
              ctaLabel={canEdit ? 'Add VTA' : undefined}
              ctaIcon="fa-plus"
              onCtaClick={canEdit ? () => navigate(ROUTES.TRUST_AGENT_CONNECT) : undefined}
              ctaTestId="trust-agents-empty-connect-button"
            />
          )}

          {!loading && !error && connections.length > 0 && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className="mb-0">No connections match your search.</p>
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <VtaConnectionsList
              connections={filtered}
              busyId={busyId}
              canEdit={canEdit}
              canDelete={canDelete}
              canRotateKeys={canRotateKeys}
              onOpen={connection => navigate(trustAgentResumePath(connection.id))}
              onVerify={handleVerify}
              onRevoke={handleRevoke}
              onRotateKey={handleRotateKey}
              onCancelRotation={handleCancelRotation}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default TrustAgentsPage;
