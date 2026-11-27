import {
  DELETE_KEPT_USER_SUCCESS,
  DELETE_OIDC_USER_NOTICE,
  DELETE_OIDC_USER_NOTICE_SHORT,
  DELETE_OIDC_USER_SUCCESS,
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
  it('explains the kept record for a user with an OIDC account', () => {
    expect(deleteConfirmNotice({ has_oidc_account: true })).toBe(DELETE_OIDC_USER_NOTICE);
    expect(DELETE_OIDC_USER_NOTICE).toContain('kept disabled');
  });

  it('has a shorter text for the users table, for an OIDC user only', () => {
    expect(deleteConfirmNotice({ has_oidc_account: true }, true)).toBe(
      DELETE_OIDC_USER_NOTICE_SHORT
    );
    expect(DELETE_OIDC_USER_NOTICE_SHORT.length).toBeLessThan(DELETE_OIDC_USER_NOTICE.length);
    expect(deleteConfirmNotice({}, true)).toBeUndefined();
  });

  it('says nothing for a user without an OIDC account', () => {
    expect(deleteConfirmNotice({})).toBeUndefined();
    expect(deleteConfirmNotice({ has_oidc_account: false })).toBeUndefined();
  });
});

describe('deleteSuccessMessage', () => {
  it('says the OIDC record was kept when the outcome is disabled', () => {
    expect(deleteSuccessMessage('disabled', { has_oidc_account: true })).toBe(
      DELETE_OIDC_USER_SUCCESS
    );
  });

  it('does not mention OIDC for a kept user who has no OIDC account', () => {
    const message = deleteSuccessMessage('disabled', {});
    expect(message).toBe(DELETE_KEPT_USER_SUCCESS);
    expect(message).not.toContain('OpenID');
  });

  it('says deleted when the record was removed or the answer names no outcome', () => {
    expect(deleteSuccessMessage('removed', { has_oidc_account: true })).toBe(DELETE_USER_SUCCESS);
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
