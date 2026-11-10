Feature: Sign-in events delivered to integrations
  A console sign-in raises `user.login`, and a sign-in that reaches credential verification and
  fails raises `user.login_failed`, as does a SAML response the gateway rejects. Both name the
  sign-in method; a failed one also names its reason, and names the user only when the account
  exists, as it is stored. Each sign-in raises one event, and a sign-in with a challenge the
  gateway did not issue raises none. The caller's answer to a failed sign-in is the same either
  way. The events match the golden events under tests/fixtures/integration_events.

  Background:
    Given an integration streams sign-in events

  Scenario: A passkey sign-in with a passkey the gateway does not hold raises a failed sign-in
    Given "alpha" is an approved console user
    And a passkey sign-in has been started for "alpha"
    When the sign-in is finished with a passkey the gateway does not hold
    Then the response status is 401
    And the stream receives a "user.login_failed" event with login method "passkey" and failure reason "invalid_credential"
    And that event has exactly the fields of a sign-in event naming an account
    And that event names the console user "alpha"
    And that event matches the golden event "user.login_failed.existing_account"
    And that event is the only sign-in event the stream receives

  Scenario: A passkey sign-in for an account awaiting approval raises a failed sign-in naming it
    Given "delta" has registered a passkey and awaits approval
    And a passkey sign-in has been started for "delta"
    When the sign-in is finished with the user's passkey
    Then the response status is 401
    And the stream receives a "user.login_failed" event with login method "passkey" and failure reason "not_approved"
    And that event has exactly the fields of a sign-in event naming an account
    And that event names the console user "delta"
    And that event is the only sign-in event the stream receives

  Scenario: A failed passkey sign-in for an unknown username names no user
    Given a passkey sign-in has been started for the unknown username "bravo"
    When the sign-in is finished with a passkey the gateway does not hold
    Then the response status is 401
    And the stream receives a "user.login_failed" event with login method "passkey" and failure reason "unknown_user"
    And that event has exactly the fields of a sign-in event naming no account
    And that event does not contain "bravo"
    And that event matches the golden event "user.login_failed.no_account"
    And that event is the only sign-in event the stream receives

  Scenario: A successful passkey sign-in raises a sign-in that names its method
    Given "charlie" is an approved console user with a passkey
    And a passkey sign-in has been started for "charlie"
    When the sign-in is finished with the user's passkey
    Then the response status is 200
    And the stream receives a "user.login" event with login method "passkey"
    And that event has exactly the fields of a sign-in event naming an account
    And that event names no failure reason
    And that event names the console user "charlie"
    And that event matches the golden event "user.login"
    And that event is the only sign-in event the stream receives

  Scenario: A rejected SAML response raises a failed sign-in that names no user
    Given console users sign in with SAML
    When a SAML response the identity provider did not sign is posted to the gateway
    Then the response status is 401
    And the stream receives a "user.login_failed" event with login method "saml" and failure reason "saml_rejected"
    And that event has exactly the fields of a sign-in event naming no account
    And that event does not contain "member@example.test"
    And that event is the only sign-in event the stream receives

  Scenario: A passkey sign-in finished with a challenge the gateway did not issue raises nothing
    When a passkey sign-in is finished with a challenge the gateway did not issue
    Then the response status is 400
    And the stream receives no sign-in event

  Scenario: An integration with Agent Watch's record content receives the event data as its record
    Given another integration streams sign-in events with Agent Watch's record content
    And "alpha" is an approved console user
    And a passkey sign-in has been started for "alpha"
    When the sign-in is finished with a passkey the gateway does not hold
    Then the response status is 401
    And the stream receives a "user.login_failed" record with login method "passkey" and failure reason "invalid_credential"
    And that record matches the golden event "user.login_failed.existing_account"
