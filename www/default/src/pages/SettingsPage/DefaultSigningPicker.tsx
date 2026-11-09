import React, { useCallback, useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { applianceSigningPayload } from '../VtaConnectionsPage/vtaConnectionHelpers';
import type { VtaConnection } from '../VtaConnectionsPage/types';

/** `local` is not a connection id, so it needs a sentinel the select can hold. */
const LOCAL = '__local__';

interface Props {
  /** Refetch the status strip once the backend actually changes. */
  onChanged: () => void;
}

/**
 * Picks the backend that signs for the whole appliance.
 *
 * Only `connected` **and** `enabled` connections carrying an active key can be
 * chosen, mirroring the backend's `assert_usable` rather than inventing a
 * second rule. A connection that is paired but has no key yet is listed and
 * disabled with the reason, because hiding it would read as "pairing did not
 * work" when the real gap is a missing key.
 */
export const DefaultSigningPicker: React.FC<Props> = ({ onChanged }) => {
  const [connections, setConnections] = useState<VtaConnection[] | null>(null);
  const [selected, setSelected] = useState<string>(LOCAL);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    try {
      const [connectionsResponse, settingsResponse] = await Promise.all([
        apiClient.fetch('/api/v1/vta/connections'),
        apiClient.fetch('/api/v1/settings'),
      ]);
      if (!connectionsResponse.ok) throw new Error(connectionsResponse.statusText);
      if (!settingsResponse.ok) throw new Error(settingsResponse.statusText);
      const list: VtaConnection[] = await connectionsResponse.json();
      const settings = await settingsResponse.json();
      setConnections(list);
      setSelected(settings?.default_signing?.connection_id ?? LOCAL);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the available backends.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const usable = (connection: VtaConnection) =>
    connection.enabled && connection.pairing.state === 'connected';

  const activeKeyId = (connection: VtaConnection) => connection.keys?.active?.key_id;

  const save = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      // An empty block clears the override, returning the appliance to
      // whatever the configuration file resolves.
      let default_signing: Record<string, string> = {};
      if (selected !== LOCAL) {
        const connection = connections?.find(c => c.id === selected);
        const payload = connection ? applianceSigningPayload(connection) : null;
        if (!payload) {
          throw new Error(
            'That connection has no context and active key yet, so it cannot sign for the appliance.'
          );
        }
        default_signing = payload;
      }
      const response = await apiClient.fetch('/api/v1/settings', {
        // The settings write route is POST, not PUT.
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ default_signing }),
      });
      if (!response.ok) throw new Error(await response.text());
      setSaved(true);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not change the signing backend.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mt-3" data-testid="default-signing-picker">
      <Form.Group className="mb-2">
        <Form.Label htmlFor="default-signing-select" className="small fw-semibold">
          Sign with
        </Form.Label>
        <Form.Select
          id="default-signing-select"
          size="sm"
          value={selected}
          disabled={saving || connections === null}
          onChange={event => {
            setSelected(event.target.value);
            setSaved(false);
          }}
        >
          <option value={LOCAL}>This gateway&apos;s own key (local)</option>
          {(connections ?? []).map(connection => {
            const ready = usable(connection) && Boolean(activeKeyId(connection));
            return (
              <option key={connection.id} value={connection.id} disabled={!ready}>
                {connection.name}
                {ready ? '' : ' — not ready: pair it and provision a key first'}
              </option>
            );
          })}
        </Form.Select>
      </Form.Group>

      {error && (
        <div className="alert alert-danger py-2 small" role="alert">
          <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
          {error}
        </div>
      )}
      {saved && !error && (
        <div className="alert alert-success py-2 small" role="status">
          <i className="fas fa-check me-2" aria-hidden="true" />
          Signing backend updated. It applies from the next request — nothing was migrated.
        </div>
      )}

      <AppButton variant="primary" size="sm" onClick={() => void save()} disabled={saving}>
        {saving ? 'Saving…' : 'Save signing backend'}
      </AppButton>
    </div>
  );
};
