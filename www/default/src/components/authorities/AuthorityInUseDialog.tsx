import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { WarningDialog } from '../shared/WarningDialog';
import { describeAuthorityUse, type AuthorityInUse } from './authorityInUse';

interface AuthorityInUseDialogProps {
  authorityName?: string;
  inUse: AuthorityInUse;
  onClose: () => void;
}

/**
 * Shown when the gateway refuses to delete an Authority that Trust Checks or Trust Recorder
 * entries use. Lists what uses it; it offers no way to delete it anyway.
 */
export const AuthorityInUseDialog: React.FC<AuthorityInUseDialogProps> = ({
  authorityName,
  inUse,
  onClose,
}) => {
  const [registryNames, setRegistryNames] = useState<ReadonlyMap<string, string>>(new Map());
  const namesRegistries = inUse.references.some(r =>
    r.uses.some(u => u.element === 'trust_recorder' && u.trustRegistryId)
  );

  useEffect(() => {
    if (!namesRegistries) return undefined;
    let alive = true;
    apiClient
      .listTrustRegistries()
      .then(list => {
        if (alive) setRegistryNames(new Map(list.map(r => [r.id, r.name])));
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [namesRegistries]);

  const registryName = (id: string) => registryNames.get(id) || id;
  const testId = 'authority-in-use-dialog';

  return (
    <WarningDialog
      testId={testId}
      title="Authority in use"
      onClose={onClose}
      footer={
        <button
          type="button"
          className="btn btn-secondary"
          data-testid={`${testId}-close`}
          onClick={onClose}
        >
          Close
        </button>
      }
    >
      <p>
        {authorityName ? <strong>{authorityName}</strong> : 'This Authority'} is used by Trust
        Checks or Trust Recorder entries. Point them at another Authority or remove them, then
        delete it.
      </p>
      <ul className="mb-0 ps-3" data-testid={`${testId}-references`}>
        {inUse.references.map(reference => (
          <li
            key={`${reference.kind}-${reference.id}`}
            className="mb-2"
            data-testid={`${testId}-${reference.kind === 'surface' ? 'surface' : 'sts-client'}-${reference.id}`}
          >
            {reference.kind === 'surface' ? (
              <>
                Surface{' '}
                <a
                  href={`/surfaces/${encodeURIComponent(reference.id)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid={`${testId}-surface-link-${reference.id}`}
                >
                  {reference.name || reference.id}
                </a>
              </>
            ) : (
              <>
                STS client <strong>{reference.name || reference.id}</strong>
              </>
            )}
            {reference.uses.length > 0 && (
              <ul className="small text-muted ps-3">
                {reference.uses.map((use, i) => (
                  <li key={i}>{describeAuthorityUse(use, registryName)}</li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      {inUse.hiddenReferences > 0 && (
        <p className="mt-2 mb-0 text-muted" data-testid={`${testId}-hidden`}>
          {inUse.hiddenReferences} more you can't view.
        </p>
      )}
    </WarningDialog>
  );
};
