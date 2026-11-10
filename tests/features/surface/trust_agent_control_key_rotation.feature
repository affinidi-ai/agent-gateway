Feature: The gateway rotates the control key it uses with its bundled trust agent
  The gateway authenticates to its bundled trust agent with a control did:key. An operator
  can move the gateway's access entry to a new key at any time, and the gateway does it on
  its own every 90 days. Only the control key changes: the signing keys, the issuer and the
  gateway's connection stay as they were.

  Scenario: An operator rotates the control key and the trust agent knows the gateway by the new key
    Given a bundled trust agent that has enrolled the gateway
    When the operator rotates the bundled control key
    Then the admin API response status is 200
    And the trust agent knows the gateway by the new did:key
    And the trust agent refused no sign-in from the gateway

  Scenario: Rotating the control key leaves the signing key and the issuer alone
    Given a bundled trust agent that has enrolled the gateway
    And the operator has rotated the bundled control key
    When the operator reads the trust agent status
    Then the bootstrap state is "connected"
    And the bootstrap signing key is still "gateway-jwt-1"
    And the trust agent was asked to create 1 signing key
    And the trust agent gave the gateway context an identity to issue as

  Scenario: The trust agent status shows when the control key was rotated and when it is next due
    Given a bundled trust agent that has enrolled the gateway
    And the operator has rotated the bundled control key
    When the operator reads the trust agent status
    Then the status shows the control key was rotated just now
    And the next rotation is due in 90 days

  Scenario: A rotation the trust agent refuses leaves the gateway on its current key
    Given a bundled trust agent that refuses to move the gateway's access entry
    When the operator rotates the bundled control key
    Then the admin API response status is 502
    And the trust agent still knows the gateway by the did:key it enrolled

  Scenario: A second rotation within ten minutes is refused
    Given a bundled trust agent that has enrolled the gateway
    And the operator has rotated the bundled control key
    When the operator rotates the bundled control key
    Then the rotation is told how long to wait

  Scenario: A user without key management rights cannot rotate the control key
    Given a bundled trust agent that has enrolled the gateway
    And human user "uma" lacks permission to manage keys
    When human user "uma" tries to rotate the bundled control key
    Then the admin API response status is 403

  Scenario: A gateway that is not connected to its bundled agent refuses to rotate
    Given a bundled trust agent that has not published its identity
    When the operator rotates the bundled control key
    Then the admin API response status is 409
