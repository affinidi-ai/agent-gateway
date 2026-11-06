Feature: API keys an Identity takes its DID from
  An Identity slot that takes its DID from an API key names a key of its own surface. The
  surface serves while that key is active. Revoking or deleting the key takes the surface out
  of service with 503 in both tenant credential isolation modes, and a save cannot add a
  revoked key or another surface's key, while a key the stored surface already named is kept.
  Deleting a surface revokes its API keys and keeps them, so no new surface can take its id.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface's Access Point does not check its callers
    And the gateway keeps its log of warnings

  Scenario: A surface whose Identity names an active API key of its own serves
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario Outline: Revoking the API key takes the surface out of service
    Given the gateway <rule mode> the credential rule "tenant_credential_isolation"
    And the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the operator has revoked API key "alpha"
    When the caller sends a request to the surface
    Then the response status is 503
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "reason=api_key_revoked"

    Examples:
      | rule mode     |
      | enforces      |
      | only warns on |

  Scenario Outline: Deleting the API key takes the surface out of service
    Given the gateway <rule mode> the credential rule "tenant_credential_isolation"
    And the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the operator has deleted API key "alpha"
    When the caller sends a request to the surface
    Then the response status is 503
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "reason=api_key_missing"

    Examples:
      | rule mode     |
      | enforces      |
      | only warns on |

  Scenario Outline: Reading the surface reports the status of the API key its Identity names
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the operator has <key change> API key "alpha"
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the surface reports API key "alpha" as "<status>"

    Examples:
      | key change | status  |
      | revoked    | revoked |
      | deleted    | missing |

  Scenario: A save cannot add a revoked API key
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the surface has an API key "charlie"
    And the operator has revoked API key "charlie"
    When the operator saves the surface with its protected Identity taking its DID from API key "charlie"
    Then the admin API response status is 400
    And the admin API error response mentions "is revoked; name an active API key of this surface"
    And the stored surface's protected Identity takes its DID from API key "alpha"

  Scenario: A surface whose API key was revoked after it was saved saves again unchanged
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the operator has revoked API key "alpha"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"
    And the stored surface's protected Identity takes its DID from API key "alpha"

  Scenario: A save cannot name another surface's API key
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the surface for route "/other" has an API key "delta"
    When the operator saves the surface with its protected Identity taking its DID from API key "delta"
    Then the admin API response status is 400
    And the admin API error response mentions "belongs to another surface; a surface names only its own API keys"
    And the stored surface's protected Identity takes its DID from API key "alpha"

  Scenario: A save naming another tenant's revoked API key does not say it is revoked
    Given the surface belongs to tenant "tenant-a"
    And the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the surface for route "/other" of tenant "tenant-b" has an API key "delta"
    And the operator has revoked API key "delta"
    When the operator saves the surface with its protected Identity taking its DID from API key "delta"
    Then the admin API response status is 400
    And the admin API error response mentions "API-key parent Surface reference is not accessible"
    And the admin API error response does not mention "revoked"
    And the stored surface's protected Identity takes its DID from API key "alpha"

  Scenario: A surface that names only its own API key moves to another tenant
    Given the surface belongs to tenant "tenant-a"
    And the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    When the operator reassigns the surface to tenant "tenant-b"
    Then the admin API response status is 200
    And the stored surface belongs to tenant "tenant-b"

  Scenario: Deleting a surface revokes its API keys and keeps them
    Given the surface has an API key "alpha"
    When the operator deletes the surface
    Then the admin API response status is 200
    And the operator reads API key "alpha" as revoked, with its surface deleted

  Scenario: A new surface cannot take the id of a deleted surface that kept API keys
    Given the surface has an API key "alpha"
    And the operator has deleted the surface
    When the operator creates a surface with the deleted surface's id
    Then the admin API response status is 400
    And the admin API error response mentions "is not available"
    And no surface with the deleted surface's id is stored
