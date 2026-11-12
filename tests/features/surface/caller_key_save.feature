Feature: Caller key rules when saving a surface
  The admin API refuses a caller key whose header is outside the caller key family
  (x-caller-key, or x-caller-key- followed by lower-case words, at most 64
  characters) or is already used by another setting of the surface, and one whose
  secret holds fewer than 32 bytes. A save that leaves the caller key out, as a
  Surface Builder save does, keeps it.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And the appliance holds a 32-byte secret "caller-keys"

  Scenario: A surface with a caller key is saved
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft derives caller keys in header "x-caller-key-memory" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "caller_key"

  Scenario: Saving a caller key for a plain http Target warns that its keys go out in clear
    Given a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft derives caller keys in header "x-caller-key-memory" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries a Warning header containing "caller_key sends caller keys in clear to a Target that is not https"

  Scenario Outline: A caller key header outside the caller key family is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft derives caller keys in header "<header>" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "caller_key.header must be x-caller-key, or x-caller-key- followed by lower-case letters and digits in words joined by single hyphens, at most 64 characters"

    Examples:
      | header                                                            |
      | X-Caller-Key                                                      |
      | x-user-vault-key                                                  |
      | authorization                                                     |
      | x-caller-key-                                                     |
      | x-caller-key-memory-of-a-very-long-header-name-past-sixty-four-ch |

  Scenario: A caller key header the Target credential uses is refused
    Given a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Caller-Key-Vendor"
    And the draft derives caller keys in header "x-caller-key-vendor" from secret "caller-keys"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "caller_key.header x-caller-key-vendor is already used by a Target or delegated credential"

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
    And the draft derives caller keys in header "x-caller-key-memory" from secret "caller-keys"
    And the operator has created the surface from the draft
    When the operator saves the surface without its caller key
    Then the admin API response status is 200
    And the stored surface derives caller keys in header "x-caller-key-memory" from secret "caller-keys"
