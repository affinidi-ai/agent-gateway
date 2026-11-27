import {
  DELETE_KEPT_USER_SUCCESS,
  DELETE_USER_SUCCESS,
  DELETE_USER_TITLE,
  deleteConfirmNotice,
  deleteSuccessMessage,
  isDeletedKeptUser,
  keptAccountDetail,
  keptAccountLabel,
  rejectSuccessMessage,
} from './userDelete';

describe('keptAccountLabel', () => {
  it('names the OpenID Connect account by subject and issuer', () => {
    expect(
      keptAccountLabel({ oidc: { issuer: 'https://idp.example.com', subject: 'sub-1' } })
    ).toBe('OpenID Connect account sub-1 at https://idp.example.com');
  });

  it('names the SAML account', () => {
    expect(keptAccountLabel({ saml_id: 'saml-1' })).toBe('SAML account saml-1');
  });

  it('has no label for a user whose record was not kept', () => {
    expect(keptAccountLabel({})).toBeNull();
  });
});

describe('DELETE_USER_TITLE', () => {
  it('says a federated user is kept and can return only when approved again', () => {
    expect(DELETE_USER_TITLE).toContain('OpenID Connect or SAML');
    expect(DELETE_USER_TITLE).toContain('approves them again');
  });

  it('says the access tokens the user holds are revoked', () => {
    expect(DELETE_USER_TITLE).toContain('Access tokens bound to the user');
    expect(DELETE_USER_TITLE).toContain('created or rotated for others');
  });
});

describe('keptAccountDetail', () => {
  it('says the record is kept disabled for the account', () => {
    expect(keptAccountDetail('SAML account saml-1')).toBe(
      'kept disabled for the SAML account saml-1'
    );
  });
});

describe('isDeletedKeptUser', () => {
  const oidc = { issuer: 'https://idp.example.com', subject: 'sub-1' };

  it('is true for a disabled user bound to a provider account', () => {
    expect(isDeletedKeptUser({ status: 'disabled', oidc })).toBe(true);
    expect(isDeletedKeptUser({ status: 'disabled', saml_id: 'saml-1' })).toBe(true);
  });

  it('is false for a user who is approved again or has no provider account', () => {
    expect(isDeletedKeptUser({ status: 'approved', oidc })).toBe(false);
    expect(isDeletedKeptUser({ status: 'disabled' })).toBe(false);
  });
});

describe('deleteConfirmNotice', () => {
  it('explains the kept record and names the provider for an OIDC or SAML user', () => {
    expect(deleteConfirmNotice({ sign_in_method: 'oidc' })).toBe(
      'This user signs in with OpenID Connect. Their record is not removed: it is kept disabled under their provider account, so their next sign-in is refused until an administrator approves them again.'
    );
    expect(deleteConfirmNotice({ sign_in_method: 'saml' })).toBe(
      'This user signs in with SAML. Their record is not removed: it is kept disabled under their provider account, so their next sign-in is refused until an administrator approves them again.'
    );
  });

  it('has a shorter text for the users table, for an OIDC or SAML user only', () => {
    const oidc = deleteConfirmNotice({ sign_in_method: 'oidc' }, true);
    expect(oidc).toBe('OpenID Connect user: the record is kept disabled, not removed.');
    expect(deleteConfirmNotice({ sign_in_method: 'saml' }, true)).toBe(
      'SAML user: the record is kept disabled, not removed.'
    );
    expect((oidc ?? '').length).toBeLessThan(
      (deleteConfirmNotice({ sign_in_method: 'oidc' }) ?? '').length
    );
    expect(deleteConfirmNotice({ sign_in_method: 'passkey' }, true)).toBeUndefined();
  });

  it('says nothing for a passkey user or one whose sign-in method is not known', () => {
    expect(deleteConfirmNotice({ sign_in_method: 'passkey' })).toBeUndefined();
    expect(deleteConfirmNotice({})).toBeUndefined();
  });
});

describe('deleteSuccessMessage', () => {
  it('names the provider whose account stays on the kept record', () => {
    expect(deleteSuccessMessage('disabled', { sign_in_method: 'oidc' })).toBe(
      'User disabled. Their OpenID Connect account stays on a disabled record and is refused at sign-in until an administrator approves them again.'
    );
    expect(deleteSuccessMessage('disabled', { sign_in_method: 'saml' })).toBe(
      'User disabled. Their SAML account stays on a disabled record and is refused at sign-in until an administrator approves them again.'
    );
  });

  it('names no provider for a kept user whose sign-in method is a passkey or not known', () => {
    for (const user of [{ sign_in_method: 'passkey' as const }, {}]) {
      const message = deleteSuccessMessage('disabled', user);
      expect(message).toBe(DELETE_KEPT_USER_SUCCESS);
      expect(message).not.toMatch(/OpenID|SAML/);
    }
  });

  it('says deleted when the record was removed or the answer names no outcome', () => {
    expect(deleteSuccessMessage('removed', { sign_in_method: 'oidc' })).toBe(DELETE_USER_SUCCESS);
    expect(deleteSuccessMessage(undefined, {})).toBe(DELETE_USER_SUCCESS);
  });
});

describe('rejectSuccessMessage', () => {
  it('says the record was kept when the outcome is disabled', () => {
    expect(rejectSuccessMessage('disabled', 'bob')).toContain(
      "User 'bob' rejected. Their record is kept"
    );
  });

  it('says rejected and deleted otherwise', () => {
    expect(rejectSuccessMessage('removed', 'bob')).toBe("User 'bob' rejected and deleted");
    expect(rejectSuccessMessage(undefined, 'bob')).toBe("User 'bob' rejected and deleted");
  });
});
