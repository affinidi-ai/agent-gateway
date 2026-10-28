import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { explainFailure } from './vtaConnectionHelpers';
import type { NewVtaConnection, PairingPayload, VtaConnection, VtaDeploymentStatus } from './types';

const BASE = '/api/v1/vta/connections';

async function readError(response: Response, endpoint?: string): Promise<string> {
  let detail = response.statusText;
  try {
    const body = await response.json();
    if (body && typeof body.error === 'string') detail = body.error;
  } catch {
    // A non-JSON body is nothing an operator can act on; keep the status text.
  }
  return explainFailure(detail, endpoint);
}

export interface VtaConnectionsState {
  connections: VtaConnection[];
  deployment: VtaDeploymentStatus | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
  create: (draft: NewVtaConnection) => Promise<VtaConnection>;
  pair: (connection: VtaConnection) => Promise<PairingPayload>;
  verify: (connection: VtaConnection) => Promise<VtaConnection>;
  provisionKey: (connection: VtaConnection) => Promise<VtaConnection>;
  revoke: (connection: VtaConnection) => Promise<void>;
}

export function useVtaConnections(): VtaConnectionsState {
  const [connections, setConnections] = useState<VtaConnection[]>([]);
  const [deployment, setDeployment] = useState<VtaDeploymentStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, status] = await Promise.all([
        apiClient.fetch(BASE),
        apiClient.fetch('/api/v1/vta/status'),
      ]);
      if (!list.ok) throw new Error(await readError(list));
      setConnections(await list.json());
      // The tier is informative, not load-bearing: a failure here must not
      // hide the connections themselves.
      setDeployment(status.ok ? await status.json() : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load VTA connections.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const replace = useCallback((updated: VtaConnection) => {
    setConnections(prev => prev.map(c => (c.id === updated.id ? updated : c)));
  }, []);

  /**
   * Create a connection, ready to pair.
   *
   * `enabled` is sent true because a connection nobody enabled can never be
   * paired or used, and the operator is creating it precisely to use it.
   * Usability is still gated by pairing state, so this grants nothing on its
   * own.
   */
  const create = useCallback(async (draft: NewVtaConnection) => {
    const response = await apiClient.fetch(BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: draft.name.trim(),
        endpoint: draft.endpoint.trim(),
        vta_did: draft.vta_did.trim(),
        // Pairing refuses without a context, so the grant can be scoped to one.
        default_context_id: draft.default_context_id.trim() || undefined,
        transport: 'https',
        enabled: true,
      }),
    });
    if (!response.ok) throw new Error(await readError(response, draft.endpoint));
    const created = (await response.json()) as VtaConnection;
    setConnections(prev => [...prev, created]);
    return created;
  }, []);

  const pair = useCallback(async (connection: VtaConnection) => {
    const response = await apiClient.fetch(`${BASE}/${encodeURIComponent(connection.id)}/pair`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error(await readError(response, connection.endpoint));
    return (await response.json()) as PairingPayload;
  }, []);

  const verify = useCallback(
    async (connection: VtaConnection) => {
      const response = await apiClient.fetch(
        `${BASE}/${encodeURIComponent(connection.id)}/verify`,
        { method: 'POST' }
      );
      // `409` means the VTA answered but the grant or identity is wrong: the
      // body is still the updated connection, so record it before surfacing
      // the problem — the operator needs to see *what* was granted.
      if (response.status === 409) {
        const updated = (await response.json()) as VtaConnection;
        replace(updated);
        throw new Error(
          explainFailure(updated.pairing.last_error ?? 'Verification failed.', connection.endpoint)
        );
      }
      if (!response.ok) throw new Error(await readError(response, connection.endpoint));
      const updated = (await response.json()) as VtaConnection;
      replace(updated);
      return updated;
    },
    [replace]
  );

  const revoke = useCallback(
    async (connection: VtaConnection) => {
      const response = await apiClient.fetch(
        `${BASE}/${encodeURIComponent(connection.id)}/revoke`,
        { method: 'POST' }
      );
      if (!response.ok) throw new Error(await readError(response, connection.endpoint));
      replace((await response.json()) as VtaConnection);
    },
    [replace]
  );

  /**
   * Mint the connection's first signing key on the agent itself.
   *
   * The caller must check there is no active key: the endpoint *rotates*, so
   * calling it on a keyed connection retires a key that is still signing.
   */
  const provisionKey = useCallback(
    async (connection: VtaConnection) => {
      const response = await apiClient.fetch(`${BASE}/${encodeURIComponent(connection.id)}/keys`, {
        method: 'POST',
      });
      if (!response.ok) throw new Error(await readError(response, connection.endpoint));
      const updated = (await response.json()) as VtaConnection;
      replace(updated);
      return updated;
    },
    [replace]
  );

  return {
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
  };
}
