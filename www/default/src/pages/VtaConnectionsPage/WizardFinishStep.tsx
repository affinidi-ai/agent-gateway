import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { TRANSPORT_LABELS } from './vtaConnectionHelpers';
import type { VtaConnection } from './types';

interface Props {
  connection: VtaConnection;
  /** Mints the connection's first key. Only called when there is none. */
  onProvisionKey: (connection: VtaConnection) => Promise<VtaConnection>;
  /** Lets the wizard hand the finished connection back to the page. */
  onSettled: (connection: VtaConnection) => void;
  /** Reports whether the appliance default should be applied on finish. */
  onDefaultChoice: (makeDefault: boolean) => void;
}

/**
 * The last wizard step: make the connection actually usable.
 *
 * Pairing proves *who* the gateway is to the agent; it does not create the key
 * that signs. A connection with no key is disabled in every picker, so there is
 * no state in which an operator would pair one and deliberately leave it
 * keyless — the key is minted here rather than offered as a choice.
 *
 * Provisioning *rotates*, so it is guarded on there being no active key: a
 * second pass would retire a key that is still signing.
 */
export const WizardFinishStep: React.FC<Props> = ({
  connection,
  onProvisionKey,
  onSettled,
  onDefaultChoice,
}) => {
  const { hasPermission } = usePermissions();
  const canProvision = hasPermission('key_management.edit');
  const canSetDefault = hasPermission('settings.edit');

  const [current, setCurrent] = useState(connection);
  const [minting, setMinting] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [makeDefault, setMakeDefault] = useState(false);
  const [existingDefault, setExistingDefault] = useState<string | null | undefined>(undefined);

  const activeKeyId = current.keys?.active?.key_id;

  // A ref, not state: setting `minting` re-runs the effect, and a cleanup
  // guard would then cancel the request its own render had just started.
  const started = useRef(false);

  useEffect(() => {
    if (started.current || activeKeyId || !canProvision) return;
    started.current = true;
    setMinting(true);
    void (async () => {
      try {
        const updated = await onProvisionKey(current);
        setCurrent(updated);
        onSettled(updated);
      } catch (e) {
        setKeyError(e instanceof Error ? e.message : 'Could not provision a key.');
      } finally {
        setMinting(false);
      }
    })();
  }, [activeKeyId, canProvision, current, onProvisionKey, onSettled]);

  // Pre-check only when the appliance has no agent default yet. Connecting a
  // second agent must never silently repoint signing for everything already
  // running against the first.
  useEffect(() => {
    void (async () => {
      try {
        const response = await apiClient.fetch('/api/v1/settings');
        const settings = response.ok ? await response.json() : null;
        const existing = settings?.default_signing?.connection_id ?? null;
        setExistingDefault(existing);
        const preCheck = canSetDefault && !existing;
        setMakeDefault(preCheck);
        onDefaultChoice(preCheck);
      } catch {
        setExistingDefault(null);
      }
    })();
  }, [canSetDefault, onDefaultChoice]);

  const choose = useCallback(
    (checked: boolean) => {
      setMakeDefault(checked);
      onDefaultChoice(checked);
    },
    [onDefaultChoice]
  );

  const ready = Boolean(activeKeyId);

  return (
    <div>
      <div
        className={`alert d-flex align-items-start ${ready ? 'alert-success' : 'alert-warning'}`}
        role="status"
      >
        <i
          className={`fas ${ready ? 'fa-circle-check' : 'fa-triangle-exclamation'} me-2 mt-1`}
          aria-hidden="true"
        />
        <div>
          {ready ? (
            <>
              <strong>Connected.</strong> This gateway can now sign through your agent.
            </>
          ) : minting ? (
            <>
              <strong>Connected.</strong> Creating a signing key on your agent…
            </>
          ) : (
            <>
              <strong>Connected, but it cannot sign yet.</strong> This connection has no signing
              key.
            </>
          )}
        </div>
      </div>

      {keyError && (
        <div className="alert alert-danger small" role="alert">
          {keyError} You can create one later from Secrets → Key Management.
        </div>
      )}

      {!canProvision && !activeKeyId && (
        <div className="alert alert-info small" role="status">
          Creating a signing key needs the <code>key_management.edit</code> permission. Ask an
          administrator to finish this from Secrets → Key Management.
        </div>
      )}

      <dl className="row small mb-3">
        <dt className="col-sm-4">Agent</dt>
        <dd className="col-sm-8">
          <code>{current.pairing.pinned_vta_did ?? current.vta_did}</code>
        </dd>
        <dt className="col-sm-4">Granted role</dt>
        <dd className="col-sm-8">{current.pairing.granted_role ?? '—'}</dd>
        <dt className="col-sm-4">Context</dt>
        <dd className="col-sm-8">
          {(current.pairing.granted_contexts ?? []).join(', ') || current.default_context_id || '—'}
        </dd>
        <dt className="col-sm-4">Transport</dt>
        <dd className="col-sm-8">{TRANSPORT_LABELS[current.transport]}</dd>
        <dt className="col-sm-4">Signing key</dt>
        <dd className="col-sm-8">
          {activeKeyId ? <code>{activeKeyId}</code> : minting ? 'creating…' : 'none'}
        </dd>
      </dl>

      {canSetDefault && (
        <Form.Check
          type="checkbox"
          id="vta-wizard-make-default"
          checked={makeDefault}
          disabled={!ready}
          onChange={event => choose(event.target.checked)}
          label={
            <span>
              Use this agent for all signing
              <span className="d-block text-muted small">
                {existingDefault
                  ? 'An agent is already the appliance default; this would replace it.'
                  : 'The appliance signs with its own key today.'}{' '}
                Change this later in Settings → System → Key management, or per surface in the
                surface editor.
              </span>
            </span>
          }
        />
      )}
    </div>
  );
};
