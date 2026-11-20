import React, { useCallback, useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import { apiClient } from '../../../../api';
import type { SurfaceSigning } from '../types';
import type { VtaConnection } from '../../../../pages/VtaConnectionsPage/types';
import { BOOTSTRAP_CONNECTION_ID } from '../../../../pages/VtaConnectionsPage/vtaConnectionHelpers';
import { ROUTES } from '../../../../routes';

type SigningType = 'local' | 'remote';

/** The two signing key sources, worded the same wherever one is chosen. */
export const SIGNING_TYPE_LABELS: Record<SigningType, string> = {
  local: 'Gateway secret',
  remote: 'Verifiable Trust Agent',
};

interface Props {
  signing?: SurfaceSigning;
  setSigning: (value: SurfaceSigning | undefined) => void;
  disabled?: boolean;
  /**
   * What the choice is for: one surface, every surface an issuer owns, or the gateway-wide
   * default. The gateway default has nothing to inherit, so it shows no inherited note and no
   * way back to one.
   */
  subject?: 'surface' | 'issuer' | 'gateway';
  /** Reports which source is shown, so a parent can offer actions that only fit one of them. */
  onTypeChange?: (type: SigningType) => void;
  /** Reports whether Verifiable Trust Agent is chosen with no agent picked yet. */
  onRemotePendingChange?: (pending: boolean) => void;
  /** The issuer that owns this surface, whose own choice a surface that sets nothing follows. */
  owner?: { name: string; signing?: SurfaceSigning };
}

/**
 * Which backend signs for this surface: this gateway's own key (**Local**) or a connected trust
 * agent (**Remote**), chosen from the connections.
 *
 * A surface that sets nothing inherits the appliance default, and says so rather than hiding that
 * nothing is configured: the type shown is the one the default resolves to, and it only becomes
 * the surface's own once the operator picks one. **Use the gateway-wide default** takes it back.
 *
 * Only `connected` + `enabled` connections carrying an active key can be chosen, mirroring the
 * backend's `assert_usable`. A connection that is paired but has no key is listed and disabled
 * with the reason, so a half-finished setup reads as what it is instead of looking like a failure.
 */
export const SurfaceSigningSection: React.FC<Props> = ({
  signing,
  setSigning,
  disabled,
  subject = 'surface',
  owner,
  onTypeChange,
  onRemotePendingChange,
}) => {
  const [connections, setConnections] = useState<VtaConnection[]>([]);
  const [loadError, setLoadError] = useState(false);
  const [connectionsLoaded, setConnectionsLoaded] = useState(false);
  const [defaultBackend, setDefaultBackend] = useState<string>('local');
  /** Remote was picked and no agent has been chosen yet, so nothing is stored for it. */
  const [remotePending, setRemotePending] = useState(false);

  const loadConnections = useCallback(() => {
    setLoadError(false);
    return apiClient
      .fetch('/api/v1/vta/connections')
      .then(response => (response.ok ? response.json() : Promise.reject(new Error('failed'))))
      .then((list: VtaConnection[]) => setConnections(list))
      .catch(() => {
        // A surface can still be saved without this list; only the Remote option becomes
        // unusable, which the load error below says.
        setLoadError(true);
      })
      .finally(() => setConnectionsLoaded(true));
  }, []);

  useEffect(() => {
    let alive = true;
    void loadConnections();
    apiClient
      .fetch('/api/v1/vta/status')
      .then(response => (response.ok ? response.json() : null))
      .then(status => {
        if (alive && status?.default_resolution?.backend) {
          setDefaultBackend(status.default_resolution.backend);
        }
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [loadConnections]);

  useEffect(() => {
    onRemotePendingChange?.(remotePending);
  }, [remotePending, onRemotePendingChange]);

  const inherited = !signing?.backend;
  // What this surface follows while it sets nothing: its issuer's choice, then the appliance default.
  const ownerSigning = inherited && owner?.signing?.backend ? owner.signing : undefined;
  const shown = signing?.backend ? signing : ownerSigning;
  const type: SigningType = remotePending
    ? 'remote'
    : shown?.backend === 'local'
      ? 'local'
      : shown?.backend
        ? 'remote'
        : defaultBackend === 'local'
          ? 'local'
          : 'remote';
  const selectedAgent = shown?.backend === 'vta' ? (shown.connection_id ?? '') : '';

  const ready = (connection: VtaConnection) =>
    connection.enabled &&
    connection.pairing.state === 'connected' &&
    Boolean(connection.keys?.active?.key_id);

  // The `[vta]` block's own record is offered once it is connected. While it is not,
  // offering it greyed out as "not ready" would suggest there is something to set up,
  // so it is left out, unless this surface already saved it, so the select is never blank.
  const listed = (connection: VtaConnection) =>
    connection.id !== BOOTSTRAP_CONNECTION_ID ||
    ready(connection) ||
    signing?.connection_id === connection.id;

  const listedConnections = connections.filter(listed);
  const noAgents = connectionsLoaded && !loadError && listedConnections.length === 0;

  useEffect(() => {
    onTypeChange?.(type);
  }, [type, onTypeChange]);

  const chooseType = (value: string) => {
    if (value === 'local') {
      setRemotePending(false);
      setSigning({ backend: 'local' });
      return;
    }
    // Remote needs an agent. Until one is chosen nothing is stored for it, so a surface never
    // saves a backend it cannot sign with.
    setRemotePending(true);
    if (signing?.backend !== 'vta') setSigning(undefined);
  };

  const chooseAgent = (id: string) => {
    if (!id) {
      setRemotePending(true);
      setSigning(undefined);
      return;
    }
    const connection = connections.find(c => c.id === id);
    if (!connection) return;
    setRemotePending(false);
    setSigning({
      backend: 'vta',
      connection_id: connection.id,
      ...(connection.default_context_id ? { context_id: connection.default_context_id } : {}),
      // JWTs name their key, so a mapping without one resolves to nothing.
      ...(connection.keys?.active?.key_id ? { key_id: connection.keys.active.key_id } : {}),
    });
  };

  const useDefault = () => {
    // Undefined, not an empty block: the backend treats "no signing" and "empty signing" alike,
    // and sending one would make an inheriting surface look configured.
    setRemotePending(false);
    setSigning(undefined);
  };

  const inheritable = subject !== 'gateway';
  const followed = ownerSigning
    ? SIGNING_TYPE_LABELS[ownerSigning.backend === 'local' ? 'local' : 'remote']
    : null;
  const help =
    (subject === 'gateway'
      ? 'Which key signs audit records and credentials for every surface that sets no source of its own, and every issuer. '
      : subject === 'issuer'
        ? 'Which key signs credentials for the surfaces this issuer owns. A surface that sets its own source keeps it. '
        : 'Which key signs credentials issued for this surface. ') +
    "Gateway secret is this gateway's own key. Verifiable Trust Agent signs through an agent you have connected (Connections → Verifiable Trust Agent), with a key the gateway does not control. " +
    (subject === 'gateway'
      ? ''
      : subject === 'issuer'
        ? 'An issuer that sets neither follows the gateway-wide default (Settings → Security → Gateway signing).'
        : "A surface that sets neither follows its issuer's source, then the gateway-wide default (Settings → Security → Gateway signing).");

  return (
    <Form.Group className="mb-3">
      <div className="d-flex align-items-center gap-1 mb-1">
        <Form.Label htmlFor="surface-signing-type-select" className="mb-0">
          Signing key source
        </Form.Label>
        <FieldHelp text={help} />
      </div>
      <div className="d-flex align-items-center gap-2">
        <Form.Select
          id="surface-signing-type-select"
          data-testid="surface-signing-type-select"
          value={type}
          disabled={disabled}
          onChange={event => chooseType(event.target.value)}
        >
          <option value="local">{SIGNING_TYPE_LABELS.local}</option>
          <option value="remote">{SIGNING_TYPE_LABELS.remote}</option>
        </Form.Select>
      </div>

      {inheritable && inherited && !remotePending && (
        <Form.Text className="d-block text-muted" data-testid="surface-signing-inherited">
          {followed
            ? `Following its issuer, ${owner?.name} (${followed}).`
            : `Following the gateway-wide default (${SIGNING_TYPE_LABELS[defaultBackend === 'local' ? 'local' : 'remote']}).`}{' '}
          Choose a source to set {subject === 'issuer' ? "this issuer's" : "this surface's"} own.
        </Form.Text>
      )}
      {inheritable && !inherited && (
        <button
          type="button"
          className="btn btn-link btn-sm p-0"
          data-testid="surface-signing-reset"
          disabled={disabled}
          onClick={useDefault}
        >
          Use the gateway-wide default
        </button>
      )}

      {type === 'remote' && (
        <div className="mt-2">
          {noAgents ? (
            <Form.Text className="d-block text-muted" data-testid="surface-signing-no-agents">
              No Verifiable Trust Agent is connected yet.
              {subject === 'gateway' ? ' Connect one with Connect VTA, then choose it here.' : ''}
            </Form.Text>
          ) : (
            <>
              <Form.Label htmlFor="surface-signing-agent-select" className="small text-muted mb-1">
                Agent
              </Form.Label>
              <Form.Select
                id="surface-signing-agent-select"
                data-testid="surface-signing-agent-select"
                size="sm"
                value={selectedAgent}
                disabled={disabled}
                onChange={event => chooseAgent(event.target.value)}
              >
                <option value="">Select a Verifiable Trust Agent…</option>
                {listedConnections.map(connection => (
                  <option key={connection.id} value={connection.id} disabled={!ready(connection)}>
                    {connection.name}
                    {ready(connection) ? '' : ' — not ready: connect it and provision a key first'}
                  </option>
                ))}
              </Form.Select>
            </>
          )}
          {subject !== 'gateway' && (
            <Form.Text className="d-block text-muted">
              <a
                href={ROUTES.TRUST_AGENT_CONNECT}
                target="_blank"
                rel="noopener noreferrer"
                data-testid="surface-signing-connect-link"
              >
                Add VTA
              </a>{' '}
              ·{' '}
              <button
                type="button"
                className="btn btn-link btn-sm p-0 align-baseline"
                data-testid="surface-signing-refresh"
                onClick={() => void loadConnections()}
              >
                Refresh
              </button>
            </Form.Text>
          )}
          {selectedAgent === '' && !noAgents && (
            <Form.Text className="d-block text-warning" data-testid="surface-signing-pick-agent">
              {subject === 'gateway'
                ? 'Choose a Verifiable Trust Agent before saving.'
                : `Choose a Verifiable Trust Agent. Until then this ${subject} follows ${
                    ownerSigning ? 'its issuer' : 'the gateway-wide default'
                  }.`}
            </Form.Text>
          )}
        </div>
      )}

      {loadError && (
        <Form.Text className="text-muted">
          Verifiable Trust Agents could not be listed, so only the gateway secret can be chosen
          here.
        </Form.Text>
      )}
      {signing?.backend === 'vta' && signing.context_id && (
        <Form.Text className="d-block text-muted">
          Signs in context <code>{signing.context_id}</code>
          {signing.key_id ? (
            <>
              {' '}
              with key <code>{signing.key_id}</code>
            </>
          ) : null}
          .
        </Form.Text>
      )}
    </Form.Group>
  );
};
