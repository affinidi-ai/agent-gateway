import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../../shared/FieldHelp';
import { apiClient } from '../../../../api';
import type { SurfaceSigning } from '../types';
import type { VtaConnection } from '../../../../pages/VtaConnectionsPage/types';

/** Not a connection id, so the select needs a sentinel for "use the default". */
const INHERIT = '__inherit__';
const LOCAL = '__local__';

interface Props {
  signing?: SurfaceSigning;
  setSigning: (value: SurfaceSigning | undefined) => void;
  disabled?: boolean;
}

/**
 * Which backend signs for this surface.
 *
 * Defaults to **inherit**, and says so rather than showing the value it would
 * resolve to: hiding that nothing is configured defeats the point of looking,
 * and it is the same rule the Key Management tab follows.
 *
 * Only `connected` + `enabled` connections carrying an active key can be
 * chosen, mirroring the backend's `assert_usable`. A connection that is paired
 * but has no key is listed and disabled with the reason, so a half-finished
 * setup reads as what it is instead of looking like a failure.
 */
export const SurfaceSigningSection: React.FC<Props> = ({ signing, setSigning, disabled }) => {
  const [connections, setConnections] = useState<VtaConnection[]>([]);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    let alive = true;
    apiClient
      .fetch('/api/v1/vta/connections')
      .then(response => (response.ok ? response.json() : Promise.reject(new Error('failed'))))
      .then((list: VtaConnection[]) => {
        if (alive) setConnections(list);
      })
      .catch(() => {
        // A surface can still be saved without this list; only the VTA option
        // becomes unavailable, which the empty select communicates.
        if (alive) setLoadError(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  const selected = (() => {
    if (!signing?.backend) return INHERIT;
    if (signing.backend === 'local') return LOCAL;
    return signing.connection_id ?? INHERIT;
  })();

  const ready = (connection: VtaConnection) =>
    connection.enabled &&
    connection.pairing.state === 'connected' &&
    Boolean(connection.keys?.active?.key_id);

  const choose = (value: string) => {
    if (value === INHERIT) {
      // Undefined, not an empty block: the backend treats "no signing" and
      // "empty signing" alike, and sending one would make an inheriting
      // surface look configured.
      setSigning(undefined);
      return;
    }
    if (value === LOCAL) {
      setSigning({ backend: 'local' });
      return;
    }
    const connection = connections.find(c => c.id === value);
    if (!connection) return;
    setSigning({
      backend: 'vta',
      connection_id: connection.id,
      ...(connection.default_context_id ? { context_id: connection.default_context_id } : {}),
      // JWTs name their key, so a mapping without one resolves to nothing.
      ...(connection.keys?.active?.key_id ? { key_id: connection.keys.active.key_id } : {}),
    });
  };

  return (
    <Form.Group className="mb-3">
      <Form.Label htmlFor="surface-signing-select">
        Signing key
        <FieldHelp text="Which backend signs credentials issued for this surface. Inherit uses whatever the appliance is set to in Settings → Key management." />
      </Form.Label>
      <Form.Select
        id="surface-signing-select"
        value={selected}
        disabled={disabled}
        onChange={event => choose(event.target.value)}
      >
        <option value={INHERIT}>Inherit the appliance default</option>
        <option value={LOCAL}>This gateway&apos;s own key (local)</option>
        {connections.map(connection => (
          <option key={connection.id} value={connection.id} disabled={!ready(connection)}>
            {connection.name}
            {ready(connection) ? '' : ' — not ready: connect it and provision a key first'}
          </option>
        ))}
      </Form.Select>
      {loadError && (
        <Form.Text className="text-muted">
          Trust agents could not be listed, so only the local key can be chosen here.
        </Form.Text>
      )}
      {signing?.backend === 'vta' && signing.context_id && (
        <Form.Text className="text-muted">
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
