Feature: Sign-in integration events
  A human user's sign-in raises the integration event `user.login`, and a sign-in that reaches
  credential verification and fails raises `user.login_failed`, as does a SAML response the
  gateway rejects. An integration whose event set holds them receives both. Both name the sign-in
  method; a failed one also names its reason, and names the user only when the account exists,
  as it is stored. Each sign-in raises one event, and completing a sign-in the gateway did not
  start raises none. The caller's answer to a failed sign-in is the same either way. The events
  match the reference events under tests/fixtures/integration_events.

  Background:
    Given an integration whose event set holds the sign-in events

  Scenario: A passkey sign-in with a passkey that is not the user's raises a failed sign-in
    Given human user "alpha" is approved
    And a passkey sign-in has been started for human user "alpha"
    When the sign-in is completed with a passkey that is not the user's
    Then the response status is 401
    And the integration receives a "user.login_failed" event with login method "passkey" and failure reason "invalid_credential"
    And that event carries only the fields of a sign-in event for an existing account
    And that event names human user "alpha"
    And that event matches the reference event "user.login_failed.existing_account"
    And the integration receives no other sign-in event

  Scenario: A passkey sign-in for an account awaiting approval raises a failed sign-in naming it
    Given human user "delta" has registered a passkey and awaits approval
    And a passkey sign-in has been started for human user "delta"
    When the sign-in is completed with the user's passkey
    Then the response status is 401
    And the integration receives a "user.login_failed" event with login method "passkey" and failure reason "not_approved"
    And that event carries only the fields of a sign-in event for an existing account
    And that event names human user "delta"
    And the integration receives no other sign-in event

  Scenario: A failed passkey sign-in for an unknown username names no user
    Given a passkey sign-in has been started for the unknown username "bravo"
    When the sign-in is completed with a passkey that is not the user's
    Then the response status is 401
    And the integration receives a "user.login_failed" event with login method "passkey" and failure reason "unknown_user"
    And that event carries only the fields of a sign-in event for no account
    And that event does not contain "bravo"
    And that event matches the reference event "user.login_failed.no_account"
    And the integration receives no other sign-in event

  Scenario: A successful passkey sign-in raises a sign-in that names its method
    Given human user "charlie" is approved and has a passkey
    And a passkey sign-in has been started for human user "charlie"
    When the sign-in is completed with the user's passkey
    Then the response status is 200
    And the integration receives a "user.login" event with login method "passkey"
    And that event carries only the fields of a sign-in event for an existing account
    And that event names no failure reason
    And that event names human user "charlie"
    And that event matches the reference event "user.login"
    And the integration receives no other sign-in event

  Scenario: A rejected SAML response raises a failed sign-in that names no user
    Given human users sign in with SAML
    When a SAML response the identity provider did not sign is posted to the gateway
    Then the response status is 401
    And the integration receives a "user.login_failed" event with login method "saml" and failure reason "saml_rejected"
    And that event carries only the fields of a sign-in event for no account
    And that event does not contain "member@example.test"
    And the integration receives no other sign-in event

  Scenario: Completing a passkey sign-in the gateway did not start raises nothing
    When a passkey sign-in is completed without a sign-in the gateway started
    Then the response status is 400
    And the integration receives no sign-in event

  Scenario: An integration with Agent Watch's template receives the event data as its record
    Given another integration uses Agent Watch's template
    And human user "alpha" is approved
    And a passkey sign-in has been started for human user "alpha"
    When the sign-in is completed with a passkey that is not the user's
    Then the response status is 401
    And that integration receives the "user.login_failed" event as a record with login method "passkey" and failure reason "invalid_credential"
    And that record matches the reference event "user.login_failed.existing_account"
