export type DeleteOutcome = 'removed' | 'disabled';

export const DELETE_USER_TITLE =
  'Delete user. A user who signs in through OpenID Connect or SAML is disabled and kept instead, so they cannot sign in until an administrator approves them again. Access tokens bound to the user, and tokens the user created or rotated for others, are revoked.';

export const DELETE_USER_SUCCESS = 'User deleted successfully';

export const DELETE_OIDC_USER_NOTICE =
  'This user signs in with OpenID Connect. Their record is not removed: it is kept disabled under their provider account, so their next sign-in is refused until an administrator approves them again.';

export const DELETE_OIDC_USER_NOTICE_SHORT =
  'OpenID Connect user: the record is kept disabled, not removed.';

export const DELETE_OIDC_USER_SUCCESS =
  'User disabled. Their OpenID Connect account stays on a disabled record and is refused at sign-in until an administrator approves them again.';

export const DELETE_KEPT_USER_SUCCESS =
  'User disabled. Their record is kept and is refused at sign-in until an administrator approves them again.';

export const KEPT_ACCOUNT_HEADING = 'Deleted:';

export const PROVIDER_ACCOUNT_HEADING = 'Provider account:';

export const DELETED_USER_NOTICE =
  'This user was deleted. Their account stays refused at sign-in until an administrator approves them again.';

export interface KeptAccount {
  oidc?: { issuer: string; subject: string };
  saml_id?: string;
}

export const keptAccountLabel = (user: KeptAccount): string | null => {
  if (user.oidc) {
    return `OpenID Connect account ${user.oidc.subject} at ${user.oidc.issuer}`;
  }
  if (user.saml_id) {
    return `SAML account ${user.saml_id}`;
  }
  return null;
};

export const keptAccountDetail = (label: string): string => `kept disabled for the ${label}`;

export const isDeletedKeptUser = (user: KeptAccount & { status: string }): boolean =>
  user.status === 'disabled' && keptAccountLabel(user) !== null;

export const deleteConfirmNotice = (
  user: { has_oidc_account?: boolean },
  compact = false
): string | undefined => {
  if (!user.has_oidc_account) {
    return undefined;
  }
  return compact ? DELETE_OIDC_USER_NOTICE_SHORT : DELETE_OIDC_USER_NOTICE;
};

export const deleteSuccessMessage = (
  outcome: DeleteOutcome | undefined,
  user: { has_oidc_account?: boolean }
): string => {
  if (outcome !== 'disabled') {
    return DELETE_USER_SUCCESS;
  }
  return user.has_oidc_account ? DELETE_OIDC_USER_SUCCESS : DELETE_KEPT_USER_SUCCESS;
};

export const rejectSuccessMessage = (outcome: DeleteOutcome | undefined, name: string): string =>
  outcome === 'disabled'
    ? `User '${name}' rejected. Their record is kept and is refused at sign-in until an administrator approves them again.`
    : `User '${name}' rejected and deleted`;
