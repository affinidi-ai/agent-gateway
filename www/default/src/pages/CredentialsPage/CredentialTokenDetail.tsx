import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';
import {
  DelegationToken,
  TokenStatus,
  consentEndValue,
  shownTime,
  tokenStatus,
} from './delegatedAccess';

interface CredentialTokenDetailProps {
  token: DelegationToken;
  now: Date;
  /** Opens the delegation audit of one user identity hash; no link is shown without it. */
  onViewActivity?: (userHash: string) => void;
}

interface DetailRow {
  label: string;
  value: React.ReactNode;
}

export const TokenStatusBadge: React.FC<{ status: TokenStatus }> = ({ status }) => (
  <span className={`badge text-bg-${status.tone}`}>{status.label}</span>
);

const copyable = (value: string, name: string, breakAnywhere = false) => (
  <>
    <code style={breakAnywhere ? { wordBreak: 'break-all' } : undefined}>{value}</code>
    <CopyButton text={value} title={`Copy ${name}`} />
  </>
);

const DetailTable: React.FC<{ rows: DetailRow[] }> = ({ rows }) => (
  <table className="table table-sm table-borderless mb-0" style={{ fontSize: '0.85rem' }}>
    <tbody>
      {rows.map(({ label, value }) => (
        <tr key={label}>
          <td className="text-muted fw-semibold" style={{ width: '140px', whiteSpace: 'nowrap' }}>
            {label}
          </td>
          <td>{value}</td>
        </tr>
      ))}
    </tbody>
  </table>
);

/** Everything the Credential Tokens tab knows of one token, shown under its row. */
const CredentialTokenDetail: React.FC<CredentialTokenDetailProps> = ({
  token,
  now,
  onViewActivity,
}) => {
  const identity: DetailRow[] = [
    { label: 'Token ID', value: copyable(token.id, 'Token ID') },
    { label: 'Provider ID', value: <strong>{token.provider_id}</strong> },
    {
      label: 'Credential Provider',
      value: copyable(token.credential_provider_id, 'Credential Provider'),
    },
    {
      label: 'Token Type',
      value: <span className="badge text-bg-info">{token.token_type}</span>,
    },
    { label: 'Agent DID', value: copyable(token.agent_did, 'Agent DID', true) },
    { label: 'User Identity', value: copyable(token.user_identity_hash, 'User Identity', true) },
    {
      label: 'Scopes',
      value: token.scopes.map(scope => (
        <span key={scope} className="badge text-bg-secondary me-1">
          {scope}
        </span>
      )),
    },
  ];
  const lifetime: DetailRow[] = [
    { label: 'Status', value: <TokenStatusBadge status={tokenStatus(token, now)} /> },
    {
      label: 'Can Refresh',
      value: token.can_refresh ? (
        <span className="badge text-bg-success">Yes</span>
      ) : (
        <span className="badge text-bg-secondary">No</span>
      ),
    },
    { label: 'Consented', value: shownTime(token.consent_granted_at) },
    { label: 'Consent Ends', value: consentEndValue(token, now) },
    { label: 'Token Expires', value: shownTime(token.expires_at) },
    { label: 'Last Used', value: shownTime(token.last_used_at) },
    { label: 'Created', value: shownTime(token.created_at) },
    { label: 'Updated', value: shownTime(token.updated_at) },
  ];

  return (
    <div
      className="px-4 py-3"
      id={`credential-token-detail-${token.id}`}
      data-testid={`credential-token-detail-${token.id}`}
    >
      <div className="row g-3">
        <div className="col-md-6">
          <DetailTable rows={identity} />
        </div>
        <div className="col-md-6">
          <DetailTable rows={lifetime} />
          {onViewActivity && (
            <AppButton
              variant="link"
              size="sm"
              className="p-0 mt-2"
              data-testid={`credential-token-view-activity-button-${token.id}`}
              onClick={() => onViewActivity(token.user_identity_hash)}
              iconStart={<i className="fas fa-clipboard-list" aria-hidden="true" />}
            >
              View this user's delegation audit
            </AppButton>
          )}
        </div>
      </div>
    </div>
  );
};

export default CredentialTokenDetail;
