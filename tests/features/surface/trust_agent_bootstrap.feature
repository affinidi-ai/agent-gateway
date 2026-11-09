Feature: A bundled trust agent connects itself on first start
  A gateway that ships with a bundled trust agent writes its own did:key for the trust agent
  to enrol, waits for the trust agent to publish its DID, pins it, authenticates, checks it
  holds exactly the bundled grant, and creates a non-exportable signing key, with no operator
  action. Anything short of that is reported on the trust agent status, and a gateway that
  never connected keeps signing with its own key.

  Scenario: A trust agent that enrolled the gateway connects with no operator action
    Given a bundled trust agent that has enrolled the gateway
    When the operator reads the trust agent status
    Then the admin API response status is 200
    And the bootstrap state is "connected"
    And the trust agent has no owner yet
    And the deployment is reported as bundled with no custody claim
    And the gateway authenticates as a did:key
    And the gateway wrote its own did:key for the trust agent to enrol
    And the trust agent was asked to create 1 signing key
    And the trust agent gave the gateway context an identity to issue as

  Scenario: The connection list shows the bundled trust agent as connected, not as waiting to be paired
    Given a bundled trust agent that has enrolled the gateway
    When the operator lists the trust agent connections
    Then the admin API response status is 200
    And the bootstrap connection is shown as connected
    And the bootstrap connection shows the bundled grant and no error

  Scenario: The key inventory shows the bundled trust agent as paired and usable
    Given a bundled trust agent that has enrolled the gateway
    When the operator reads the key inventory
    Then the admin API response status is 200
    And the inventory lists the bundled trust agent as paired and usable

  Scenario: Verifying the bundled trust agent's connection is refused, so signing is not interrupted
    Given a bundled trust agent that has enrolled the gateway
    When the operator verifies the bundled trust agent connection
    Then the admin API response status is 409
    And the trust agent was asked to create 1 signing key

  Scenario: A trust agent that has not published its identity is waited for, and signing stays local
    Given a bundled trust agent that has not published its identity
    When the operator reads the trust agent status
    Then the admin API response status is 200
    And the gateway signs with its own local key because the bundled trust agent is "waiting_for_vta"
    And the gateway wrote its own did:key for the trust agent to enrol
    And the trust agent was asked to create 0 signing keys

  Scenario: A trust agent that refuses the gateway is reported and no key is created
    Given a bundled trust agent that refuses the gateway
    When the operator reads the trust agent status
    Then the admin API response status is 200
    And the gateway signs with its own local key because the bundled trust agent is "enrolment_refused"
    And the trust agent was asked to create 0 signing keys

  Scenario: A trust agent that granted more than the bundled grant is refused, not trusted
    Given a bundled trust agent that granted the gateway more than the bundled grant
    When the operator reads the trust agent status
    Then the admin API response status is 200
    And the gateway signs with its own local key because the bundled trust agent is "enrolment_refused"
    And the trust agent was asked to create 0 signing keys
