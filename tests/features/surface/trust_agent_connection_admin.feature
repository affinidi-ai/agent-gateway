Feature: A trust agent connection is not cut off from what signs through it unnoticed
  Revoking a trust agent connection stops everything that signs through it. While the
  gateway default, a surface, a variant or an issuer still names the connection, a revoke
  is refused with 409 naming them, unless the operator acknowledges it. Pointing a connected
  connection at another trust agent is refused the same way, and once done the connection has
  to be paired again. A connection's endpoint is https, or plain http only to a loopback
  address.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: Revoking a connection a surface signs through is refused and names the surface
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the surface signs through the trust agent connection "shared-agent"
    When the operator revokes the trust agent connection "shared-agent"
    Then the admin API response status is 409
    And the admin API error response mentions "still signs for surface"

  Scenario: Revoking a connection a surface signs through proceeds once acknowledged
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the surface signs through the trust agent connection "shared-agent"
    When the operator revokes the trust agent connection "shared-agent" acknowledging what stops signing
    Then the admin API response status is 200

  Scenario: Revoking a connection nothing signs through proceeds
    Given the appliance holds the trust agent connection "idle-agent"
    When the operator revokes the trust agent connection "idle-agent"
    Then the admin API response status is 200

  Scenario: Pointing a connection a surface signs through at another trust agent is refused
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the surface signs through the trust agent connection "Custom VTA"
    When the operator points the custom connection at another trust agent
    Then the admin API response status is 409
    And the admin API error response mentions "still signs for surface"
    And the custom connection can still sign

  Scenario: Pointing a connection a surface signs through at another trust agent proceeds once acknowledged
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the surface signs through the trust agent connection "Custom VTA"
    When the operator points the custom connection at another trust agent acknowledging what stops signing
    Then the admin API response status is 200
    And the custom connection has to be paired again

  Scenario: Pointing a connection nothing signs through at another trust agent resets its pairing
    Given the operator has connected a custom trust agent that reads the gateway's published DID
    When the operator points the custom connection at another trust agent
    Then the admin API response status is 200
    And the custom connection has to be paired again

  Scenario: A connection whose endpoint is plain http to another host is refused
    When the operator adds a trust agent connection at "http://trust-agent.example.test"
    Then the admin API response status is 400
    And the admin API error response mentions "https"
