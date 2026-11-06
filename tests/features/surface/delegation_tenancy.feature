Feature: Tenant reads of delegation vault tokens and audit records
  A delegation vault token and a delegation audit record belong to the tenant
  of their credential provider. A tenant's access token reads only its own
  tenant's, in the Credential Delegation Audit Log, the VP Audit Log and the
  delegation vault, and another tenant's vault token, or one of an
  appliance-wide provider, answers like a missing one. An access token scoped
  by required headers alone reads none, and a tenant's access token revokes
  none. An administrator, and an appliance-wide access token, reads every
  tenant's.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And tenant "tenant-a" owns the credential provider "calendar-a"
    And tenant "tenant-b" owns the credential provider "calendar-b"
    And the appliance-wide credential provider "calendar-global" exists
    And the audit log holds a token injection of each credential provider and a revoke naming no provider
    And the delegation vault holds a token of each credential provider

  Scenario: A tenant token reads only its own tenant's records in the Credential Delegation Audit Log
    When a token of tenant "tenant-a" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the audit read shows only the token injection of credential provider "calendar-a"

  Scenario: A tenant token reads only its own tenant's records in the VP Audit Log
    When a token of tenant "tenant-a" reads the VP Audit Log
    Then the audit read response status is 200
    And the audit read shows only the token injection of credential provider "calendar-a"

  Scenario: An access token scoped by required headers alone reads no record in the Credential Delegation Audit Log
    When an access token scoped by required headers alone reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the audit read shows no record

  Scenario: An administrator reads every tenant's records in the Credential Delegation Audit Log
    Given operator "ada" has the "administrator" role
    When administrator "ada" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the audit read shows the token injection of every credential provider and the revoke naming no provider

  Scenario: An administrator reads every tenant's records in the VP Audit Log
    Given operator "ada" has the "administrator" role
    When administrator "ada" reads the VP Audit Log
    Then the audit read response status is 200
    And the audit read shows the token injection of every credential provider and the revoke naming no provider

  Scenario: A tenant token lists only its own tenant's vault tokens
    When a token of tenant "tenant-a" lists the delegation vault
    Then the admin API response status is 200
    And the vault list shows only the token of credential provider "calendar-a"

  Scenario: A tenant token reads its own tenant's vault token
    When a token of tenant "tenant-a" reads the vault token of credential provider "calendar-a"
    Then the admin API response status is 200
    And the vault read shows the token of credential provider "calendar-a"

  Scenario: Another tenant's vault token answers like a missing one
    When a token of tenant "tenant-a" reads the vault token of credential provider "calendar-b"
    Then the admin API response status is 404
    And the vault read answers that the vault token is not found

  Scenario: An appliance-wide provider's vault token answers a tenant token like a missing one
    When a token of tenant "tenant-a" reads the vault token of credential provider "calendar-global"
    Then the admin API response status is 404
    And the vault read answers that the vault token is not found

  Scenario: A missing vault token answers that it is not found
    When a token of tenant "tenant-a" reads a vault token that does not exist
    Then the admin API response status is 404
    And the vault read answers that the vault token is not found

  Scenario: An access token scoped by required headers alone lists no vault token
    When an access token scoped by required headers alone lists the delegation vault
    Then the admin API response status is 200
    And the vault list is empty

  Scenario: An access token scoped by required headers alone reads no vault token
    When an access token scoped by required headers alone reads the vault token of credential provider "calendar-a"
    Then the admin API response status is 404
    And the vault read answers that the vault token is not found

  Scenario: An administrator lists every tenant's vault tokens
    When the operator lists the delegation vault
    Then the admin API response status is 200
    And the vault list shows the token of every credential provider

  Scenario: An appliance-wide access token lists every tenant's vault tokens
    When an appliance-wide access token lists the delegation vault
    Then the admin API response status is 200
    And the vault list shows the token of every credential provider

  Scenario: An appliance-wide access token reads the vault token of an appliance-wide provider
    When an appliance-wide access token reads the vault token of credential provider "calendar-global"
    Then the admin API response status is 200
    And the vault read shows the token of credential provider "calendar-global"

  Scenario Outline: A tenant token cannot revoke a vault token
    When a token of tenant "tenant-a" revokes the vault token of credential provider "<provider>"
    Then the admin API response status is 403

    Examples:
      | provider   |
      | calendar-a |
      | calendar-b |

  Scenario: The delegation vault keeps the tokens a tenant token tried to revoke
    Given a token of tenant "tenant-a" has tried to revoke the vault token of credential provider "calendar-a"
    And a token of tenant "tenant-a" has tried to revoke the vault token of credential provider "calendar-b"
    When the operator lists the delegation vault
    Then the admin API response status is 200
    And the vault list shows the token of every credential provider
