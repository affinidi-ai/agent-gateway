Feature: The gateway rotates the control key it uses with its trust agent
  The gateway authenticates to the trust agent in its [vta] block with a control did:key it
  keeps in a file. An operator can move the gateway's access entry to a new key at any time,
  and the gateway can do it on its own on a schedule. Only the control key changes: the
  signing keys, the issuer and the gateway's connection stay as they were. A gateway whose
  control identity is a published did:webvh has no did:key to rotate this way.

  Scenario: An operator rotates the control key and the trust agent knows the gateway by the new key
    Given a trust agent that knows the gateway by its control did:key
    When the operator rotates the control key
    Then the admin API response status is 200
    And the trust agent knows the gateway by the new did:key
    And the trust agent refused no sign-in from the gateway

  Scenario: Rotating the control key leaves the signing key alone
    Given a trust agent that knows the gateway by its control did:key
    And the operator has rotated the control key
    When the operator reads the trust agent status
    Then the gateway signs through the trust agent
    And the trust agent was asked to create 0 signing keys

  Scenario: The trust agent status shows when the control key was rotated and when it is next due
    Given a trust agent that knows the gateway by its control did:key
    And the gateway is set to rotate its control key every 90 days
    And the operator has rotated the control key
    When the operator reads the trust agent status
    Then the status shows the control key was rotated just now
    And the next rotation is due in 90 days

  Scenario: A rotation the trust agent refuses leaves the gateway on its current key
    Given a trust agent that refuses to move the gateway's access entry
    When the operator rotates the control key
    Then the admin API response status is 502
    And the trust agent still knows the gateway by the did:key it was granted

  Scenario: A second rotation within ten minutes is refused
    Given a trust agent that knows the gateway by its control did:key
    And the operator has rotated the control key
    When the operator rotates the control key
    Then the rotation is told how long to wait

  Scenario: A user without key management rights cannot rotate the control key
    Given a trust agent that knows the gateway by its control did:key
    And human user "uma" lacks permission to manage keys
    When human user "uma" tries to rotate the control key
    Then the admin API response status is 403

  Scenario: A gateway whose control identity is a did:webvh refuses to rotate
    Given a trust agent that knows the gateway by its published did:webvh
    When the operator rotates the control key
    Then the admin API response status is 404
