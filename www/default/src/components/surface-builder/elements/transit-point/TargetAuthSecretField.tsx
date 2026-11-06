import React from 'react';
import { Button, Form } from 'react-bootstrap';
import AddResourceLink from '../../../shared/AddResourceLink';
import { SecretOptions, type SecretOption } from '../../../shared/SecretOptions';
import { deepLinks } from '../../../../utils/deepLinks';
import { splitByTenant } from '../../../../utils/tenantScope';
import { useSurfaceTenant } from '../../SurfaceMetaContext';
import { useTargetAuthSecrets } from './useTargetAuthSecrets';

const FIELD_ID = 'transit-point-target-auth-secret';
const NOTE_STYLE = { fontSize: '10px' };

interface TargetAuthSecretFieldProps {
  value: string;
  onChange: (secretId: string) => void;
  error?: string;
}

function outsideTenantMessage(secret: SecretOption): string {
  return secret.tenant_id
    ? 'This secret belongs to another tenant, so the gateway refuses it. Pick one from this surface’s tenant.'
    : 'This secret is appliance-wide. It stops working when tenant isolation is enforced; pick one from this surface’s tenant.';
}

/** The secret a Transit Point's static-secret target authentication sends, picked from the secrets store. */
const TargetAuthSecretField: React.FC<TargetAuthSecretFieldProps> = ({
  value,
  onChange,
  error,
}) => {
  const ownerTenant = useSurfaceTenant();
  const { secrets, status, refreshing, reload } = useTargetAuthSecrets();
  const ready = status === 'ready';
  const { offered, outside } = splitByTenant(secrets, ownerTenant);
  const missing = ready && value !== '' && !secrets.some(secret => secret.secret_id === value);
  const unlisted = !ready && value !== '';
  const outsideChoice = outside.find(secret => secret.secret_id === value);

  return (
    <Form.Group className="mt-2">
      <Form.Label className="small text-muted mb-1" htmlFor={FIELD_ID}>
        Secret Reference
      </Form.Label>
      <div className="d-flex gap-1">
        <Form.Select
          size="sm"
          id={FIELD_ID}
          data-testid={FIELD_ID}
          value={value}
          onChange={e => onChange(e.target.value)}
          disabled={status === 'loading'}
          isInvalid={!!error}
        >
          <option value="">
            {status === 'loading' ? '-- Loading secrets... --' : '-- Select a secret --'}
          </option>
          <SecretOptions secrets={secrets} ownerTenant={ownerTenant} value={value} />
          {(missing || unlisted) && (
            <option value={value}>{missing ? `${value} (not found)` : value}</option>
          )}
        </Form.Select>
        {ready && (
          <Button
            variant="outline-secondary"
            size="sm"
            title="Refresh secret list"
            aria-label="Refresh secret list"
            data-testid={`${FIELD_ID}-refresh`}
            onClick={reload}
            disabled={refreshing}
          >
            <i className={`fas fa-sync-alt${refreshing ? ' fa-spin' : ''}`} aria-hidden="true" />
          </Button>
        )}
      </div>
      {error && (
        <div
          className="invalid-feedback d-block"
          style={NOTE_STYLE}
          data-testid={`${FIELD_ID}-error`}
        >
          {error}
        </div>
      )}
      {missing && (
        <Form.Text
          className="text-warning d-block"
          style={NOTE_STYLE}
          data-testid={`${FIELD_ID}-missing`}
        >
          This secret no longer exists. Pick another one; saving will fail until you do.
        </Form.Text>
      )}
      {outsideChoice && (
        <Form.Text
          className="text-warning d-block"
          style={NOTE_STYLE}
          data-testid={`${FIELD_ID}-outside-tenant`}
        >
          {outsideTenantMessage(outsideChoice)}
        </Form.Text>
      )}
      {ready && (
        <Form.Text className="text-muted d-block" style={NOTE_STYLE}>
          {offered.length === 0 ? 'No secrets configured yet. ' : 'Don’t see the one you need? '}
          <AddResourceLink to={deepLinks.secret} testid={`${FIELD_ID}-add-link`}>
            Add secret
          </AddResourceLink>
        </Form.Text>
      )}
      {status === 'failed' && (
        <Form.Text
          className="text-warning d-block"
          style={NOTE_STYLE}
          data-testid={`${FIELD_ID}-load-error`}
        >
          Couldn’t load secrets.{' '}
          <button
            type="button"
            className="btn btn-link btn-sm p-0 align-baseline"
            style={NOTE_STYLE}
            onClick={reload}
            data-testid={`${FIELD_ID}-retry`}
          >
            Try again
          </button>
        </Form.Text>
      )}
      {status === 'denied' && (
        <Form.Text
          className="text-warning d-block"
          style={NOTE_STYLE}
          data-testid={`${FIELD_ID}-denied`}
        >
          You don’t have access to secrets. Ask an administrator.
        </Form.Text>
      )}
    </Form.Group>
  );
};

export default TargetAuthSecretField;
