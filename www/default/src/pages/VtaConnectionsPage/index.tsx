import React, { useCallback, useMemo, useState } from 'react';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { EmptyState } from '../../components/shared/EmptyState';
import SearchInput from '../../components/shared/SearchInput';
import { showToast } from '../../utils/toaster';
import { ConnectVtaWizard } from './ConnectVtaWizard';
import { NewVtaConnectionForm } from './NewVtaConnectionForm';
import { VtaConnectionsList } from './VtaConnectionsList';
import { VtaTierBanner } from './VtaTierBanner';
import { useVtaConnections } from './useVtaConnections';
import type { NewVtaConnection, VtaConnection } from './types';

/**
 * VTA connections — which Verifiable Trust Agent signs for this gateway, and
 * what state each connection's pairing is in.
 */
const VtaConnectionsPage: React.FC = () => {
  const { hasPermission } = usePermissions();
  const {
    connections,
    deployment,
    loading,
    error,
    reload,
    create,
    pair,
    verify,
    provisionKey,
    revoke,
  } = useVtaConnections();
  const [search, setSearch] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [pairing, setPairing] = useState<VtaConnection | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);

  const canEdit = hasPermission('vta_connections.edit');
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
        await revoke(connection);
        showToast('success', `${connection.name} is revoked and can no longer sign.`);
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'Revoke failed.');
      } finally {
        setBusyId(null);
      }
    },
    [confirmRevoke, revoke]
  );

  /** Create, then go straight to pairing: a connection is of no use unpaired. */
  const handleCreate = useCallback(
    async (draft: NewVtaConnection) => {
      const created = await create(draft);
      setCreating(false);
      setPairing(created);
    },
    [create]
  );

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">Trust Agent</h1>
        <div className="d-flex align-items-center gap-2">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search by name, DID or address…"
          />
          {canEdit && (
            <AppButton
              variant="primary"
              onClick={() => setCreating(true)}
              iconStart={<i className="fas fa-plus me-1" aria-hidden="true" />}
            >
              Connect an agent
            </AppButton>
          )}
        </div>
      </div>

      {creating && (
        <NewVtaConnectionForm onCancel={() => setCreating(false)} onCreate={handleCreate} />
      )}

      <VtaTierBanner deployment={deployment} />

      {pairing && (
        <ConnectVtaWizard
          connection={pairing}
          deployment={deployment}
          onPair={pair}
          onVerify={verify}
          onProvisionKey={provisionKey}
          onClose={() => {
            setPairing(null);
            void reload();
          }}
        />
      )}

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-robot me-2" aria-hidden="true" />
            Connections
            <Badge
              value={filtered.length}
              suffix={search ? ` of ${connections.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length} VTA connections`}
            />
          </h6>
          <AppButton variant="outline-secondary" size="sm" onClick={() => void reload()}>
            Refresh
          </AppButton>
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
              body="This gateway signs with its own in-process key. Connect an agent to move signing to it — you keep administration of the agent, and the gateway only ever receives a sign-only grant in one context."
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
              onOpen={setPairing}
              onVerify={handleVerify}
              onRevoke={handleRevoke}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default VtaConnectionsPage;
