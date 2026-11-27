Feature: Verifying a connection checks which trust agent answered
  A trust agent signs its answer to the gateway's authentication with the key of its DID.
  Verifying a connection pins that DID, and a later answer signed as another DID, or not
  signed at all, takes the connection out of use. An agent that cannot answer for now says
  nothing about the grant, so the connection keeps signing.

  Scenario: A trust agent that signs its answers as another DID is not kept connected
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the custom trust agent signs its answers as another DID
    When the operator verifies the custom connection
    Then the admin API response status is 409
    And the custom connection is no longer connected and names the DID that answered

  Scenario: A trust agent that does not sign its answers is not kept connected
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the custom trust agent stops signing its answers
    When the operator verifies the custom connection
    Then the admin API response status is 502
    And the custom connection is no longer connected and keeps the trust agent DID it pinned

  Scenario: A trust agent that answers 503 while it restarts stays connected
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the custom trust agent answers every request with 503
    When the operator verifies the custom connection
    Then the admin API response status is 502
    And the custom connection can still sign

  Scenario: Renaming a connected connection keeps it signing
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    When the operator renames the custom connection
    Then the admin API response status is 200
    And the custom connection can still sign
