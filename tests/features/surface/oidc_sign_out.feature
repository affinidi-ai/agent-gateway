Feature: OpenID Connect sign-out
  In OIDC mode a sign-out reaches both ends. Signing out of the dashboard ends the session and,
  while logout.rp_initiated is on and the provider publishes a sign-out address, sends the browser
  there with the session's ID token as the hint and the dashboard as the way back, so the person is
  signed out at the provider too (RP-initiated logout). Signing out at the provider ends the
  dashboard sessions of that provider session: the provider posts a signed logout token
  (back-channel logout), which the gateway accepts only from the provider, once, and never an ID
  token in its place. logout.backchannel set to false removes the back-channel logout address.

  Background:
    Given human users sign in with OpenID Connect

  Scenario: Signing out of the dashboard ends the session
    Given "mallory" has signed in with OpenID Connect carrying the roles "gw-all"
    When "mallory" signs out of the dashboard
    Then the session "mallory" was handed is refused

  Scenario: Signing out of the dashboard signs the person out at the provider too
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    When "mallory" signs out of the dashboard
    Then the sign-out sends the browser to the provider, naming the sign-in of "mallory" in the provider session "op-session-1"

  Scenario: With RP-initiated logout off, signing out of the dashboard stays in the dashboard
    Given oidc.json sets "logout.rp_initiated" to false
    And "mallory" has signed in with OpenID Connect carrying the roles "gw-all"
    When "mallory" signs out of the dashboard
    Then the sign-out leaves the browser in the dashboard
    And the session "mallory" was handed is refused

  Scenario: Signing out at the provider ends the dashboard session of that provider session only
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    And "mallory" has signed in with OpenID Connect in the provider session "op-session-2" carrying the roles "gw-all"
    When the provider signs "mallory" out of the provider session "op-session-1"
    Then the response status is 200
    And the session "mallory" was handed in the provider session "op-session-1" is refused
    And the session "mallory" was handed in the provider session "op-session-2" signs them in with the role "user"

  Scenario: A logout naming only the account ends every dashboard session of that account
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    And "mallory" has signed in with OpenID Connect in the provider session "op-session-2" carrying the roles "gw-all"
    When the provider signs "mallory" out of every provider session
    Then the response status is 200
    And the session "mallory" was handed in the provider session "op-session-1" is refused
    And the session "mallory" was handed in the provider session "op-session-2" is refused

  Scenario: A logout token sent a second time is refused and ends no session
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    And the provider has signed "mallory" out of the provider session "op-session-1"
    And "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    When the provider sends its last logout token again
    Then the back-channel logout is refused as "invalid_request"
    And the session "mallory" was handed signs them in with the role "user"

  Scenario: A logout token signed with a key the provider never published is refused
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    When the provider signs "mallory" out of the provider session "op-session-1" with a key it never published
    Then the back-channel logout is refused as "invalid_request"
    And the session "mallory" was handed signs them in with the role "user"

  Scenario: An ID token posted as a logout token is refused and ends no session
    Given "mallory" has signed in with OpenID Connect in the provider session "op-session-1" carrying the roles "gw-all"
    When the provider posts an ID token for "mallory" as a logout token
    Then the back-channel logout is refused as "invalid_request"
    And the session "mallory" was handed signs them in with the role "user"

  Scenario: With back-channel logout off, the gateway offers no back-channel logout address
    Given oidc.json sets "logout.backchannel" to false
    When the provider signs "mallory" out of the provider session "op-session-1"
    Then the response status is 404
