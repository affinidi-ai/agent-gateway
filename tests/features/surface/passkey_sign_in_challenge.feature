Feature: Passkey sign-in and registration do not tell whether an account exists
  A passkey sign-in challenge names the passkeys of an approved account. For any other username,
  unknown or awaiting approval, it names decoy credentials with no transports, the same on every
  challenge for that username: usually one 20-byte ID, sometimes one of another common length,
  sometimes two or three. No authenticator holds a decoy, so that sign-in fails like any other.
  Registering a username that already has an account, approved or awaiting approval, is answered
  as a new registration and changes nothing, and every registration is answered 25 ms after the
  username is checked, so neither the answer nor its timing tells whether it exists. A username
  longer than 256 bytes is refused, so no challenge holds a larger one, and a client IP may start
  at most 20 sign-ins and registrations a minute.

  Scenario: A sign-in for an unknown username names stable decoy credentials
    When passkey sign-ins are started twice for "bravo"
    Then both sign-in challenges name the same decoy credentials

  Scenario: A sign-in for an account awaiting approval names decoys, not its passkey
    Given human user "delta" has registered a passkey and awaits approval
    When passkey sign-ins are started twice for "delta"
    Then both sign-in challenges name the same decoy credentials
    And the sign-in challenge does not name the passkey of human user "delta"

  Scenario Outline: A <ceremony> for a username longer than 256 bytes is refused
    When a passkey <ceremony> is started for a username of 257 bytes
    Then the response status is 400

    Examples:
      | ceremony     |
      | sign-in      |
      | registration |

  Scenario: A client that starts more than 20 passkey sign-ins in a minute is refused
    When 21 passkey sign-ins are started for "bravo"
    Then the response status is 429
    And the response says when to retry

  Scenario: A sign-in for an approved user names the user's passkey
    Given human user "alpha" is approved and has a passkey
    When a passkey sign-in is started for "alpha"
    Then the sign-in challenge names only the passkey of human user "alpha"

  Scenario: Registering the username of an approved account is answered as a new registration
    Given human user "alpha" is approved and has a passkey
    When another passkey is registered for the username "alpha"
    Then the response status is 200
    And human user "alpha" is listed once, with status "approved"
    And human user "alpha" still signs in with the passkey they registered
    And the other passkey cannot sign in as human user "alpha"

  Scenario Outline: A registration is answered 25 ms after the username check, taken or new
    Given human user "alpha" is approved and has a passkey
    When a passkey is registered for the username "<username>"
    Then the response status is 200
    And the registration was answered no sooner than 25 ms

    Examples:
      | username |
      | alpha    |
      | echo     |

  Scenario: Registering the username of an account awaiting approval is answered as a new registration
    Given human user "delta" has registered a passkey and awaits approval
    When another passkey is registered for the username "delta"
    Then the response status is 200
    And human user "delta" is listed once, with status "new"
