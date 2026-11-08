Feature: Target authentication rules when saving a surface
  The admin API refuses a new or changed Target authentication, on the Target or on a
  Transit Point, that sets a header it may not set or a value format that could split the
  header, whatever the credential policy says, and refuses two Transit Points with the same id
  on create or update. The refusal names the field that breaks the rule.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"

  Scenario: A Target authentication that meets every rule is saved
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft's Target authentication formats its value as "Token {value}"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "credential_policy.target_"

  Scenario Outline: A Target authentication header that is not an HTTP header name is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "<header>"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_name must be an HTTP header name"

    Examples:
      | header    |
      | X Target  |
      | X-Target: |

  Scenario Outline: A reserved header cannot carry the Target credential
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "<header>"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_name must not be the reserved header <reserved>"

    Examples:
      | header            | reserved          |
      | transfer-encoding | Transfer-Encoding |
      | Host              | Host              |
      | x-transit-token   | X-Transit-Token   |
      | X-Caller-Did      | X-Caller-Did      |
      | mcp-session-id    | Mcp-Session-Id    |

  Scenario Outline: A header format with a line break or NUL is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target authentication formats its value as "Bearer {value}" followed by a <character>
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_format must not contain CR, LF or NUL"

    Examples:
      | character |
      | CR        |
      | LF        |
      | NUL       |

  Scenario Outline: A header format without exactly one value placeholder is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target authentication formats its value as "<format>"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_format must contain {value} exactly once"

    Examples:
      | format         |
      | Bearer         |
      | {value}{value} |

  Scenario: A Target credential cannot use the header a credential binding sends
    Given the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    And the operator has created the credential provider "bound" using secrets "provider-id-secret" and "provider-password-secret"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "x-bound-token"
    And the draft injects a delegated credential from credential provider "bound" as header "X-Bound-Token"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_name x-bound-token is already sent by a credential binding"

  Scenario: A Target credential cannot use a header the Access Point maps to metadata
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "x-tenant"
    And the draft's Access Point maps caller header "X-Tenant" to metadata field "tenant"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_name x-tenant is already sent by header metadata mapping"

  Scenario: A Target credential cannot use the header that forwards the caller's JWT Bearer token
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "Authorization"
    And the draft's Access Point forwards the caller's JWT Bearer token in header "Authorization"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth.header_name Authorization is already sent by source authentication"

  Scenario: A Target credential on its own header beside a binding and a metadata mapping is saved
    Given the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    And the operator has created the credential provider "bound" using secrets "provider-id-secret" and "provider-password-secret"
    And a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft injects a delegated credential from credential provider "bound" as header "X-Bound-Token"
    And the draft's Access Point maps caller header "X-Tenant" to metadata field "tenant"
    When the operator creates the surface from the draft
    Then the admin API response status is 201

  Scenario: A Transit Point that checks its callers saves its Target credential
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    When the operator creates the surface from the draft
    Then the admin API response status is 201

  Scenario: Two Transit Points with their own ids are saved
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And the draft has Transit Point "supplier" that sends secret "target-key" in header "X-Supplier-Key"
    And Transit Point "supplier" in the draft requires a transit token
    And the target endpoint of Transit Point "supplier" in the draft is an https URL
    When the operator creates the surface from the draft
    Then the admin API response status is 201

  Scenario: Two Transit Points with the same id are refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the draft has Transit Point "supplier" that sends secret "target-key" in header "X-Supplier-Key"
    And Transit Point "supplier" in the draft requires a transit token
    And Transit Point "supplier" in the draft has the id of Transit Point "partner"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "duplicate id 'partner-id'"

  Scenario: A reserved header cannot carry a Transit Point's Target credential
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Transit-Token"
    And Transit Point "partner" in the draft requires a transit token
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "transit.points['partner'].target_auth.header_name must not be the reserved header X-Transit-Token"

  Scenario: A Transit Point header format without exactly one value placeholder is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the Target authentication of Transit Point "partner" in the draft formats its value as "Bearer"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "transit.points['partner'].target_auth.header_format must contain {value} exactly once"

  Scenario: A Transit Point header format with one value placeholder is saved
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And the Target authentication of Transit Point "partner" in the draft formats its value as "Bearer {value}"
    When the operator creates the surface from the draft
    Then the admin API response status is 201

  Scenario: Saving a surface whose Transit Points keep their own ids succeeds
    Given a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And the draft has Transit Point "supplier" that sends secret "target-key" in header "X-Supplier-Key"
    And Transit Point "supplier" in the draft requires a transit token
    And the target endpoint of Transit Point "supplier" in the draft is an https URL
    And the operator has created the surface from the draft
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"

  Scenario: Saving a surface that gives a Transit Point the id of another is refused
    Given a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And the draft has Transit Point "supplier" that sends secret "target-key" in header "X-Supplier-Key"
    And Transit Point "supplier" in the draft requires a transit token
    And the target endpoint of Transit Point "supplier" in the draft is an https URL
    And the operator has created the surface from the draft
    When the operator saves the surface with Transit Point "supplier" taking the id of Transit Point "partner"
    Then the admin API response status is 400
    And the admin API error response mentions "duplicate id 'partner-id'"
    And the stored surface has the description "BDD-created surface"
