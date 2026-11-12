Feature: Caller key rules when saving a surface
  The admin API refuses a caller key whose header is not a lower-case HTTP header
  name, is one the gateway reserves, reads or sets itself, or is already used by
  another setting of the surface, and one whose secret holds fewer than 32 bytes.
  A save that leaves the caller key out, as a Surface Builder save does, keeps it.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And the appliance holds a 32-byte secret "caller-keys"

  Scenario: A surface with a caller key is saved
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft derives caller keys in header "x-user-vault-key" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 201

  Scenario Outline: A caller key header the surface may not use is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft derives caller keys in header "<header>" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "<refusal>"

    Examples:
      | header          | refusal                                                                             |
      | X-Caller-Key    | caller_key.header must be lower case                                                |
      | x-transit-token | caller_key.header must not be the reserved header X-Transit-Token                   |
      | authorization   | caller_key.header must not be authorization, which the gateway reads or sets itself |
      | x-target-key    | caller_key.header x-target-key is already used by a Target or delegated credential  |

  Scenario: A caller key header the Access Point reads its callers' API keys from is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft derives caller keys from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "caller_key.header x-caller-key is already used by source authentication"

  Scenario: A caller key secret shorter than 32 bytes is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft derives caller keys from secret "target-key"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "caller_key.secret_id must name a secret of at least 32 bytes"

  Scenario: A save that leaves the caller key out keeps it
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft derives caller keys in header "x-user-vault-key" from secret "caller-keys"
    And the operator has created the surface from the draft
    When the operator saves the surface without its caller key
    Then the admin API response status is 200
    And the stored surface derives caller keys in header "x-user-vault-key" from secret "caller-keys"
