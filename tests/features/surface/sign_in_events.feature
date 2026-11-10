Feature: Sign-in events delivered to integrations
  A console sign-in raises `user.login`, and a sign-in that reaches credential verification and
  fails raises `user.login_failed`, as does a SAML response the gateway rejects. Both name the
  sign-in method; a failed one also names its reason, and names the user only when the account
  exists, as it is stored. The caller's answer to a failed sign-in is the same either way.

  Background:
    Given an integration streams sign-in events to Redis

  Scenario: A passkey sign-in with a passkey the gateway does not hold raises a failed sign-in
    Given "alpha" is an approved console user
    And a passkey sign-in has been started for "alpha"
    When the sign-in is finished with a passkey the gateway does not hold
    Then the response status is 401
    And the Redis stream receives a "user.login_failed" event with login method "passkey" and failure reason "invalid_credential"
    And that event names the console user "alpha"

  Scenario: A failed passkey sign-in for an unknown username names no user
    Given a passkey sign-in has been started for the unknown username "bravo"
    When the sign-in is finished with a passkey the gateway does not hold
    Then the response status is 401
    And the Redis stream receives a "user.login_failed" event with login method "passkey" and failure reason "unknown_user"
    And that event names no user
    And that event does not contain "bravo"

  Scenario: A successful passkey sign-in raises a sign-in that names its method
    Given "charlie" is an approved console user with a passkey
    And a passkey sign-in has been started for "charlie"
    When the sign-in is finished with the user's passkey
    Then the response status is 200
    And the Redis stream receives a "user.login" event with login method "passkey"
    And that event names the console user "charlie"

  Scenario: A rejected SAML response raises a failed sign-in that names no user
    Given console users sign in with SAML
    When a SAML response the identity provider did not sign is posted to the gateway
    Then the response status is 401
    And the Redis stream receives a "user.login_failed" event with login method "saml" and failure reason "saml_rejected"
    And that event names no user
