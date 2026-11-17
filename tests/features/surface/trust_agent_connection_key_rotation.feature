Feature: The gateway rotates the control key of a connection the operator added
  A connection added by hand authenticates to its trust agent as a did:webvh the gateway
  publishes. An operator can replace the key inside that DID: the DID, and the grant the
  operator made on the trust agent, stay as they are.

  Scenario: An operator rotates a connection's control key and the DID does not change
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    When the operator rotates the custom connection's control key
    Then the admin API response status is 200
    And the connection keeps the DID that was granted
    And the trust agent finds only the new key published for that DID

  Scenario: After the rotation the connection signs in with the new key
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the operator has rotated the custom connection's control key
    When the operator verifies the custom connection
    Then the admin API response status is 200
    And the trust agent accepted the gateway signing in with the new key

  Scenario: A new key the trust agent refuses is rolled back and the old key keeps working
    Given the gateway rolls a refused rotation back after ten seconds
    And the operator has connected a custom trust agent that reads the gateway's published DID
    And the custom trust agent does not take a new key
    When the operator rotates the custom connection's control key
    Then the admin API response status is 502
    And the trust agent finds only the original key published for that DID
    And the trust agent saw the gateway sign in with the original key last

  Scenario: Editing a connection after a rotation keeps its rotated key
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the operator has rotated the custom connection's control key
    When the operator renames the custom connection
    Then the admin API response status is 200
    And the connection still names the rotated key after the edit

  Scenario: The connection list shows when the control key was rotated
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the operator has rotated the custom connection's control key
    When the operator lists the trust agent connections
    Then the admin API response status is 200
    And the custom connection shows when its control key was rotated and no rotation under way

  Scenario: A user without key management rights cannot rotate a connection's control key
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And human user "uma" lacks permission to manage keys on the custom connection
    When human user "uma" tries to rotate the custom connection's control key
    Then the admin API response status is 403

  Scenario: A connection that authenticates as a did:key cannot be rotated this way
    Given the operator has connected a custom trust agent as a did:key
    When the operator rotates the custom connection's control key
    Then the admin API response status is 409
