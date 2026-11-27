export type DeleteOutcome = 'removed' | 'disabled';

export type SignInMethod = 'passkey' | 'oidc' | 'saml';

type KeptSignInMethod = Exclude<SignInMethod, 'passkey'>;

interface DeletableUser {
  sign_in_method?: SignInMethod;
}

const PROVIDER_NAME: Record<KeptSignInMethod, string> = {
  oidc: 'OpenID Connect',
  saml: 'SAML',
};

const keptSignInMethod = (user: DeletableUser): KeptSignInMethod | undefined =>
  user.sign_in_method === 'oidc' || user.sign_in_method === 'saml'
    ? user.sign_in_method
    : undefined;

export const DELETE_USER_TITLE =
  'Delete user. A user who signs in through OpenID Connect or SAML is disabled and kept instead, so they cannot sign in until an administrator approves them again. Access tokens bound to the user, and tokens the user created or rotated for others, are revoked.';

export const DELETE_USER_SUCCESS = 'User deleted successfully';

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

export const deleteConfirmNotice = (user: DeletableUser, compact = false): string | undefined => {
  const method = keptSignInMethod(user);
  if (!method) {
    return undefined;
  }
  if (compact) {
    return `${PROVIDER_NAME[method]} user: the record is kept disabled, not removed.`;
  }
  return `This user signs in with ${PROVIDER_NAME[method]}. Their record is not removed: it is kept disabled under their provider account, so their next sign-in is refused until an administrator approves them again.`;
};

export const deleteSuccessMessage = (
  outcome: DeleteOutcome | undefined,
  user: DeletableUser
): string => {
  if (outcome !== 'disabled') {
    return DELETE_USER_SUCCESS;
  }
  const method = keptSignInMethod(user);
  if (!method) {
    return DELETE_KEPT_USER_SUCCESS;
  }
  return `User disabled. Their ${PROVIDER_NAME[method]} account stays on a disabled record and is refused at sign-in until an administrator approves them again.`;
};

export const rejectSuccessMessage = (outcome: DeleteOutcome | undefined, name: string): string =>
  outcome === 'disabled'
    ? `User '${name}' rejected. Their record is kept and is refused at sign-in until an administrator approves them again.`
    : `User '${name}' rejected and deleted`;
