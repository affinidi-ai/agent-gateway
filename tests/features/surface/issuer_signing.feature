Feature: An issuer chooses which backend signs for the surfaces it owns
  An issuer can name a trust agent connection to sign through. A surface it owns that sets no
  signing of its own follows it, ahead of the appliance default. The issuer may only name a
  connection its own tenant owns or one that belongs to the whole appliance, and a backend the
  gateway cannot sign with is refused. An empty choice hands the issuer back to the appliance
  default.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: An issuer takes a trust agent to sign for its surfaces
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    When the operator saves the issuer "Research" signing through the trust agent connection "shared-agent"
    Then the admin API response status is 200
    And the issuer "Research" signs through the trust agent connection "shared-agent"

  Scenario: An issuer is handed back to the appliance default
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    When the operator clears the signing of the issuer "Research"
    Then the admin API response status is 200
    And the issuer "Research" follows the appliance default

  Scenario: An issuer that sets no signing follows the appliance default
    Given the operator has created the issuer "Research"
    Then the issuer "Research" follows the appliance default

  Scenario: A tenant's issuer cannot sign through another tenant's connection
    Given tenant "tenant-a" holds the trust agent connection "agent-a"
    And the operator has created the issuer "Orders" owned by tenant "tenant-b"
    When the operator saves the issuer "Orders" signing through the trust agent connection "agent-a"
    Then the admin API response status is 400
    And the issuer "Orders" follows the appliance default

  Scenario: A tenant's issuer can sign through its own tenant's connection
    Given tenant "tenant-b" holds the trust agent connection "agent-b"
    And the operator has created the issuer "Orders" owned by tenant "tenant-b"
    When the operator saves the issuer "Orders" signing through the trust agent connection "agent-b"
    Then the admin API response status is 200

  Scenario: A backend the gateway cannot sign with is refused
    Given the operator has created the issuer "Research"
    When the operator saves the issuer "Research" signing through a hardware module
    Then the admin API response status is 400
    And the issuer "Research" follows the appliance default

  Scenario: The key inventory shows a surface following the trust agent of its issuer
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    And the operator has made the surface owned by the issuer "Research"
    When the operator reads the key inventory
    Then the key inventory shows the surface signing through the trust agent connection "shared-agent" on behalf of the issuer "Research"

  Scenario: A surface with its own signing is not reported as following its issuer
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    And the operator has made the surface owned by the issuer "Research"
    And the operator has saved the surface signing as the gateway's own key
    When the operator reads the key inventory
    Then the key inventory shows the surface signing with the gateway's own key and not following an issuer
