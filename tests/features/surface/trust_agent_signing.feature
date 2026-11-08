Feature: A surface signs only through a trust agent connection its tenant may use
  A trust agent connection holds the authority to sign as its owner. A surface may name
  a connection in its signing settings only if its own tenant owns that connection or the
  connection belongs to the whole appliance; any other save is refused with 400. A
  connection that does not exist is refused the same way, so the answer never reveals
  which connection ids another tenant has.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: A tenant's surface cannot sign through another tenant's connection
    Given tenant "tenant-a" holds the trust agent connection "agent-a"
    And tenant "tenant-b" holds the secret "orders-key"
    And the operator has created the surface for route "/orders" owned by tenant "tenant-b" authenticating its target with secret "orders-key"
    When the operator saves the surface signing through the trust agent connection "agent-a"
    Then the admin API response status is 400
    And the admin API error response mentions "does not reference a trust agent connection this surface may sign through"

  Scenario: A tenant's surface can sign through its own tenant's connection
    Given tenant "tenant-b" holds the trust agent connection "agent-b"
    And tenant "tenant-b" holds the secret "orders-key"
    And the operator has created the surface for route "/orders" owned by tenant "tenant-b" authenticating its target with secret "orders-key"
    When the operator saves the surface signing through the trust agent connection "agent-b"
    Then the admin API response status is 200

  Scenario: A tenant's surface can sign through an appliance-wide connection
    Given the appliance holds the trust agent connection "shared-agent"
    And tenant "tenant-b" holds the secret "orders-key"
    And the operator has created the surface for route "/orders" owned by tenant "tenant-b" authenticating its target with secret "orders-key"
    When the operator saves the surface signing through the trust agent connection "shared-agent"
    Then the admin API response status is 200

  Scenario: A tenant's surface is refused a connection that does not exist, the same way
    Given tenant "tenant-b" holds the secret "orders-key"
    And the operator has created the surface for route "/orders" owned by tenant "tenant-b" authenticating its target with secret "orders-key"
    When the operator saves the surface signing through a trust agent connection that does not exist
    Then the admin API response status is 400
    And the admin API error response mentions "does not reference a trust agent connection this surface may sign through"

  Scenario: An appliance-wide surface cannot sign through a tenant's connection
    Given tenant "tenant-a" holds the trust agent connection "agent-a"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    When the operator saves the surface signing through the trust agent connection "agent-a"
    Then the admin API response status is 400
    And the admin API error response mentions "does not reference a trust agent connection this surface may sign through"
