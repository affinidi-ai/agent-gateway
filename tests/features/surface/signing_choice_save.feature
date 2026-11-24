Feature: A signing choice is checked the same way wherever it is saved
  A surface, an issuer and the gateway-wide default each choose which backend signs. A choice
  that names a trust agent must name a key to sign tokens with and a connection its owner may
  sign through. The gateway-wide default may only sign through an existing connection that
  belongs to the whole appliance. Changing a choice is key management: it needs the
  key_management.edit permission, while a save that leaves the choice as stored does not.
  A variant signs with its surface's choice and cannot set its own.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: The gateway-wide default signs through an appliance-wide connection
    Given the appliance holds the trust agent connection "shared-agent"
    When the operator sets the gateway-wide signing through the trust agent connection "shared-agent"
    Then the admin API response status is 200
    And the gateway-wide signing goes through the trust agent connection "shared-agent"

  Scenario: The gateway-wide default cannot sign through a tenant's connection
    Given tenant "tenant-a" holds the trust agent connection "agent-a"
    When the operator sets the gateway-wide signing through the trust agent connection "agent-a"
    Then the admin API response status is 400
    And the admin API error response mentions "belongs to the whole appliance"
    And the gateway has no gateway-wide signing choice

  Scenario: The gateway-wide default cannot name a connection that does not exist
    When the operator sets the gateway-wide signing through a trust agent connection that does not exist
    Then the admin API response status is 400
    And the gateway has no gateway-wide signing choice

  Scenario: A gateway-wide trust agent choice that names no key to sign tokens with is refused
    Given the appliance holds the trust agent connection "shared-agent"
    When the operator sets the gateway-wide signing through the trust agent connection "shared-agent" without naming a key
    Then the admin API response status is 400
    And the admin API error response mentions "key_id"
    And the gateway has no gateway-wide signing choice

  Scenario: An access token without key_management.edit cannot change the gateway-wide default
    Given the appliance holds the trust agent connection "shared-agent"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.edit"
    When the personal access token sets the gateway-wide signing through the trust agent connection "shared-agent"
    Then the admin API response status is 403
    And the gateway has no gateway-wide signing choice

  Scenario: An access token with key_management.edit changes the gateway-wide default
    Given the appliance holds the trust agent connection "shared-agent"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.edit,key_management.edit"
    When the personal access token sets the gateway-wide signing through the trust agent connection "shared-agent"
    Then the admin API response status is 200
    And the gateway-wide signing goes through the trust agent connection "shared-agent"

  Scenario: A power user cannot change an issuer's signing
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    And operator "pete" has the "poweruser" role
    When operator "pete" saves the issuer "Research" signing through the trust agent connection "shared-agent"
    Then the admin API response status is 403
    And the issuer "Research" follows the appliance default

  Scenario: A power user can rename an issuer and leave its signing as it is
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    And operator "pete" has the "poweruser" role
    When operator "pete" renames the issuer "Research" to "Research and Development" leaving its signing as it is
    Then the admin API response status is 200
    And the issuer "Research" signs through the trust agent connection "shared-agent"

  Scenario: An access token without key_management.edit cannot change a surface's signing
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view,surfaces.edit"
    When the personal access token saves the surface signing through the trust agent connection "shared-agent"
    Then the admin API response status is 403
    And the admin API error response mentions "key_management.edit"

  Scenario: An access token without key_management.edit can save a surface whose signing it leaves as it is
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the operator has saved the surface signing as the gateway's own key
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view,surfaces.edit"
    When the personal access token saves the surface with the description "Orders API"
    Then the admin API response status is 200

  Scenario: An access token without key_management.edit cannot move a surface onto an issuer that signs elsewhere
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view,surfaces.edit"
    When the personal access token moves the surface to the issuer "Research"
    Then the admin API response status is 403
    And the admin API error response mentions "key_management.edit"

  Scenario: An access token without key_management.edit can move a surface between issuers that sign alike
    Given the operator has created the issuer "Research"
    And the operator has created the issuer "Sales"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    And the operator has made the surface owned by the issuer "Research"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view,surfaces.edit"
    When the personal access token moves the surface to the issuer "Sales"
    Then the admin API response status is 200

  Scenario: A variant that sets its own signing is refused
    Given the appliance holds the trust agent connection "shared-agent"
    And the appliance holds the secret "orders-key"
    And the operator has created the appliance-wide surface for route "/orders" authenticating its target with secret "orders-key"
    When the operator saves the surface with a variant that signs through the trust agent connection "shared-agent"
    Then the admin API response status is 400
    And the admin API error response mentions "a variant cannot override"

  Scenario: A connection an issuer signs through cannot move to a tenant
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has created the issuer "Research"
    And the operator has saved the issuer "Research" signing through the trust agent connection "shared-agent"
    When the operator reassigns the trust agent connection "shared-agent" to tenant "tenant-a"
    Then the admin API response status is 409
    And the admin API error response mentions "issuer signing"

  Scenario: A connection a surface signs through cannot move to another tenant
    Given tenant "tenant-b" holds the trust agent connection "agent-b"
    And tenant "tenant-b" holds the secret "orders-key"
    And the operator has created the surface for route "/orders" owned by tenant "tenant-b" authenticating its target with secret "orders-key"
    And the operator has saved the surface signing through the trust agent connection "agent-b"
    When the operator reassigns the trust agent connection "agent-b" to tenant "tenant-a"
    Then the admin API response status is 409
    And the admin API error response mentions "surface signing"

  Scenario: The connection of the gateway-wide default cannot move to a tenant
    Given the appliance holds the trust agent connection "shared-agent"
    And the operator has set the gateway-wide signing through the trust agent connection "shared-agent"
    When the operator reassigns the trust agent connection "shared-agent" to tenant "tenant-a"
    Then the admin API response status is 409
    And the admin API error response mentions "gateway-wide default signing"

  Scenario: An issuer cannot move to a tenant that may not use the connection it signs through
    Given tenant "tenant-a" holds the trust agent connection "agent-a"
    And the operator has created the issuer "Orders" owned by tenant "tenant-a"
    And the operator has saved the issuer "Orders" signing through the trust agent connection "agent-a"
    When the operator reassigns the issuer "Orders" to tenant "tenant-b"
    Then the admin API response status is 409
