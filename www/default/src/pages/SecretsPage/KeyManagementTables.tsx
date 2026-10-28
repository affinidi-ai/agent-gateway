import React from 'react';
import type { ConnectionInventory } from './keyManagementTypes';

/**
 * Keys a connection publishes.
 *
 * `kid` leads every row: it is the one value that correlates a token in a log
 * to the key that signed it, which is the question this table exists to
 * answer.
 */
export const KeyInventoryTable: React.FC<{ connection: ConnectionInventory }> = ({
  connection,
}) => {
  if (connection.keys.length === 0) {
    return (
      <p className="small text-muted mb-0">
        No keys provisioned yet. This connection is not signing anything.
      </p>
    );
  }
  return (
    <div className="table-responsive">
      <table className="table table-sm mb-0">
        <thead>
          <tr>
            <th>kid</th>
            <th>Status</th>
            <th>Public key</th>
            <th>Retired</th>
          </tr>
        </thead>
        <tbody>
          {connection.keys.map(key => (
            <tr key={key.key_id}>
              <td>
                <code>{key.key_id}</code>
                {key.label && <div className="small text-muted">{key.label}</div>}
              </td>
              <td>
                <span
                  className={`badge text-bg-${key.status === 'active' ? 'success' : 'secondary'}`}
                >
                  {key.status}
                </span>
              </td>
              <td className="small text-muted text-truncate" style={{ maxWidth: '18rem' }}>
                {key.public_key ? <code>{key.public_key}</code> : '—'}
              </td>
              <td className="small text-muted">
                {key.retired_at ? new Date(key.retired_at).toLocaleString() : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {connection.keys.some(k => k.status === 'retiring') && (
        <p className="small text-muted mt-2 mb-0">
          Retired keys are still published so the tokens they signed keep verifying. They are never
          deleted.
        </p>
      )}
    </div>
  );
};

/** Which surface or variant signs with what. */
export const SurfaceMappingTable: React.FC<{
  mappings: import('./keyManagementTypes').SurfaceMapping[];
}> = ({ mappings }) => (
  <div className="table-responsive">
    <table className="table table-sm table-hover mb-0">
      <thead>
        <tr>
          <th>Surface</th>
          <th>Backend</th>
          <th>Context</th>
          <th>Key</th>
        </tr>
      </thead>
      <tbody>
        {mappings.map(mapping => (
          <tr key={`${mapping.surface_id}:${mapping.variant_id ?? ''}`}>
            <td>
              {mapping.surface_name}
              {mapping.variant_alias && (
                <span className="badge text-bg-secondary ms-2">{mapping.variant_alias}</span>
              )}
            </td>
            <td>
              {mapping.inherits ? (
                // Showing the resolved value would hide that nothing is
                // configured — which is what the operator is checking.
                <span className="text-muted fst-italic">inherit</span>
              ) : (
                mapping.backend
              )}
            </td>
            <td className="small">
              {mapping.context_id ? (
                <code>{mapping.context_id}</code>
              ) : (
                <span className="text-muted" title={`Would use ${mapping.derived_context}`}>
                  —
                </span>
              )}
            </td>
            <td className="small">{mapping.key_id ? <code>{mapping.key_id}</code> : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);
