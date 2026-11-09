import React, { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { AppButton } from '../../components/shared/AppButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { showToast } from '../../utils/toaster';
import { KeyInventoryTable, SurfaceMappingTable } from './KeyManagementTables';
import { RotateKeyControl } from './RotateKeyControl';
import type { ConnectionInventory, KeyInventory } from './keyManagementTypes';

/**
 * Key Management — every key this appliance signs with, which surface maps to
 * what, and which contexts no surface claims any more.
 *
 * Read-mostly by design: the only mutation is rotation, and rotation only ever
 * *adds* a key and retires the previous one.
 */
const KeyManagementTab: React.FC = () => {
  const { hasPermission } = usePermissions();
  const [inventory, setInventory] = useState<KeyInventory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [provisioning, setProvisioning] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null);
  const [newKeyId, setNewKeyId] = useState('');

  const canEdit = hasPermission('key_management.edit');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/key-management/inventory');
      if (!response.ok) throw new Error(`Failed to load the key inventory: ${response.statusText}`);
      const payload = await response.json();
      // This tab mounts alongside the rest of the Secrets page, so a payload it
      // cannot read must become this tab's error rather than an exception
      // during render — that would unmount Secrets, API keys and Certificates
      // along with it. Every list the render walks is checked, not just the
      // first one reached.
      const lists = ['connections', 'mappings', 'orphaned_contexts'] as const;
      if (!payload || lists.some(key => !Array.isArray(payload[key]))) {
        throw new Error('The key inventory response was not understood.');
      }
      setInventory(payload);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load the key inventory.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const rotate = useCallback(
    async (connection: ConnectionInventory) => {
      // Two-step: rotation changes which key signs from the next request on,
      // so it uses the shared destructive confirm even though nothing is lost.
      if (confirmRotate !== connection.connection_id) {
        setConfirmRotate(connection.connection_id);
        showToast('error', 'Click Rotate again to start signing with the new key.');
        return;
      }
      setConfirmRotate(null);
      setRotating(connection.connection_id);
      try {
        const response = await apiClient.fetch(
          `/api/v1/vta/connections/${encodeURIComponent(connection.connection_id)}/rotate`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key_id: newKeyId.trim() }),
          }
        );
        if (!response.ok) {
          const body = await response.json().catch(() => null);
          throw new Error(body?.error ?? `Rotation failed: ${response.statusText}`);
        }
        setNewKeyId('');
        showToast('success', `${connection.name} now signs with ${newKeyId.trim()}.`);
        await load();
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'Rotation failed.');
      } finally {
        setRotating(null);
      }
    },
    [confirmRotate, newKeyId, load]
  );

  const provision = useCallback(
    async (connection: ConnectionInventory) => {
      // Not destructive and not a rotation: a connection with no key cannot
      // sign at all, so this is the step that makes it usable. No confirm.
      setProvisioning(connection.connection_id);
      try {
        const response = await apiClient.fetch(
          `/api/v1/vta/connections/${encodeURIComponent(connection.connection_id)}/keys`,
          { method: 'POST' }
        );
        if (!response.ok) {
          const body = await response.json().catch(() => null);
          throw new Error(body?.error ?? `Could not provision a key: ${response.statusText}`);
        }
        showToast('success', `${connection.name} can now sign.`);
        await load();
      } catch (e) {
        showToast('error', e instanceof Error ? e.message : 'Could not provision a key.');
      } finally {
        setProvisioning(null);
      }
    },
    [load]
  );

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger">
        <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
        {error}
        <AppButton variant="outline-danger" size="sm" className="ms-3" onClick={() => void load()}>
          Retry
        </AppButton>
      </div>
    );
  }

  if (!inventory) return null;

  return (
    <div className="py-3">
      <div
        className={`alert ${inventory.custody_claim ? 'alert-info' : 'alert-warning'} d-flex align-items-start`}
        role="status"
      >
        <i className="fas fa-circle-info me-2 mt-1" aria-hidden="true" />
        <div>
          <strong>Deployment: {inventory.tier}.</strong>{' '}
          {inventory.custody_claim
            ? 'Keys are held by a separately-operated agent.'
            : 'This is not a key custody tier — the keys are not held by a separate party.'}
        </div>
      </div>

      {inventory.connections.length === 0 ? (
        <EmptyState
          icon="fa-key"
          title="No agent keys"
          body="This gateway signs with its own in-process key. Connect a Verifiable Trust Agent from the Trust Agent page to manage keys here."
        />
      ) : (
        inventory.connections.map(connection => (
          <div className="card shadow mb-3" key={connection.connection_id}>
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                {connection.name}
                <span
                  className={`badge text-bg-${connection.usable ? 'success' : 'secondary'} ms-2`}
                >
                  {connection.usable ? 'signing' : connection.pairing_state}
                </span>
              </h6>
              <span className="small text-muted">{connection.transport}</span>
            </div>
            <div className="card-body">
              <KeyInventoryTable connection={connection} />
              {canEdit && connection.keys.length === 0 && (
                <div className="d-flex align-items-center gap-2 mt-2">
                  <AppButton
                    variant="primary"
                    size="sm"
                    disabled={provisioning === connection.connection_id}
                    onClick={() => void provision(connection)}
                  >
                    {provisioning === connection.connection_id
                      ? 'Provisioning…'
                      : 'Provision a signing key'}
                  </AppButton>
                  <span className="small text-muted">
                    The key is generated inside the trust agent and cannot be exported.
                  </span>
                </div>
              )}
              {canEdit && connection.keys.length > 0 && (
                <RotateKeyControl
                  connection={connection}
                  keyId={newKeyId}
                  rotating={rotating === connection.connection_id}
                  onKeyIdChange={setNewKeyId}
                  onRotate={c => void rotate(c)}
                />
              )}
            </div>
          </div>
        ))
      )}

      {inventory.mappings.length > 0 && (
        <div className="card shadow mb-3">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">Surface mapping</h6>
          </div>
          <div className="card-body">
            <SurfaceMappingTable mappings={inventory.mappings} />
          </div>
        </div>
      )}

      {inventory.orphaned_contexts.length > 0 && (
        <div className="alert alert-warning" role="status">
          <strong>Contexts no surface claims.</strong> Deleting a surface deliberately does not
          delete its keys, because artifacts they signed must stay verifiable. Clean these up on the
          agent when you are sure nothing still needs them:
          <ul className="mb-0 mt-2 small">
            {inventory.orphaned_contexts.map(name => (
              <li key={name}>
                <code>{name}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default KeyManagementTab;
