import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import SecretSelector, { Secret } from '../../../shared/SecretSelector';

interface SecretMeta {
  secret_id: string;
  name: string;
  secret_type?: string;
  tags?: string[];
}

const SECRET_PREFIX = '$SECRET:';

interface MppSecretFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  helpText?: React.ReactNode;
  required?: boolean;
}

/**
 * Secret picker for an MPP key field. Stores the selection as a
 * `$SECRET:<secret_id>` reference resolved server-side by `src/mpp/secrets.rs`,
 * so the value never lands in the surface config. A pre-existing `$VAR`/literal
 * value from an older config stays selectable and is not dropped on save.
 */
const MppSecretField: React.FC<MppSecretFieldProps> = ({
  label,
  value,
  onChange,
  helpText,
  required,
}) => {
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get<SecretMeta[]>('/secrets/')
      .then(({ data }) => {
        if (!cancelled) setSecrets(data || []);
      })
      .catch(() => {
        // Non-fatal: the picker just shows no options; the field stays required.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const raw = (value || '').trim();
  const isSecretRef = raw.startsWith(SECRET_PREFIX);
  const selectedId = isSecretRef ? raw.slice(SECRET_PREFIX.length) : '';
  const legacyValue = raw && !isSecretRef ? raw : '';
  const legacyIsEnvRef = legacyValue.startsWith('$');

  const options: Secret[] = useMemo(() => {
    const mapped: Secret[] = secrets.map(s => ({
      id: s.secret_id,
      name: s.name,
      secret_type: s.secret_type,
    }));
    // Keep the selected secret visible even if the list hasn't loaded it yet.
    if (selectedId && !mapped.some(s => s.id === selectedId)) {
      const existing = secrets.find(s => s.secret_id === selectedId);
      mapped.unshift({
        id: selectedId,
        name: existing ? existing.name : `${selectedId} (current)`,
        secret_type: existing?.secret_type,
      });
    }
    return mapped;
  }, [secrets, selectedId]);

  return (
    <>
      <SecretSelector
        secrets={options}
        selectedSecretId={selectedId}
        onChange={id => onChange(id ? `${SECRET_PREFIX}${id}` : '')}
        label={label}
        required={required}
        placeholder={secrets.length === 0 ? 'No secrets available' : 'Select a secret…'}
        helpText={undefined}
      />
      {legacyValue && (
        <div className="alert alert-warning py-2 mb-2" style={{ fontSize: '11px' }}>
          <i className="fas fa-exclamation-triangle me-1" />
          {legacyIsEnvRef ? (
            <>
              Using a legacy environment-variable reference <code>{legacyValue}</code>. Pick a
              secret above to replace it.
            </>
          ) : (
            <>A legacy literal value is set. Pick a secret above to replace it.</>
          )}
        </div>
      )}
      {helpText && (
        <small className="text-muted d-block mt-1" style={{ fontSize: '11px' }}>
          {helpText}
        </small>
      )}
    </>
  );
};

export default MppSecretField;
