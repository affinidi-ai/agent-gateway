import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import type { ConnectionInventory } from './keyManagementTypes';

interface RotateKeyControlProps {
  connection: ConnectionInventory;
  keyId: string;
  rotating: boolean;
  onKeyIdChange: (value: string) => void;
  onRotate: (connection: ConnectionInventory) => void;
}

/**
 * Start signing with a new key.
 *
 * The previous key is retired, never deleted — a verifier picks between keys
 * by `kid`, so dropping the old public half would invalidate every token it
 * signed that is still in flight. The control says so, because "rotate" reads
 * like a replacement.
 */
export const RotateKeyControl: React.FC<RotateKeyControlProps> = ({
  connection,
  keyId,
  rotating,
  onKeyIdChange,
  onRotate,
}) => (
  <div className="mt-3">
    <div className="d-flex gap-2 align-items-center">
      <label className="form-label mb-0 small" htmlFor={`kid-${connection.connection_id}`}>
        New key id
      </label>
      <input
        id={`kid-${connection.connection_id}`}
        className="form-control form-control-sm"
        style={{ maxWidth: '18rem' }}
        value={keyId}
        placeholder="Provision it on the agent first, then name it here"
        onChange={e => onKeyIdChange(e.target.value)}
      />
      <AppButton
        variant="outline-danger"
        size="sm"
        disabled={!keyId.trim() || rotating}
        onClick={() => onRotate(connection)}
      >
        {rotating ? 'Rotating…' : 'Rotate'}
      </AppButton>
    </div>
    <p className="small text-muted mb-0 mt-1">
      The current key keeps being published, so tokens it already signed stay verifiable.
    </p>
  </div>
);
