Feature: API keys an Identity takes its DID from
  An Identity slot that takes its DID from an API key names a key of its own surface. The
  surface serves while that key is active. Revoking or deleting the key takes the surface out
  of service with 503 in both tenant credential isolation modes, and a save cannot add a
  revoked key or another surface's key, while a key the stored surface already named is kept.
  Deleting a surface revokes its API keys and keeps them, so no new surface can take its id
  until those keys are deleted. A gateway that starts Active, or a Standby one that becomes
  Active, revokes the active API keys of surfaces that no longer exist.

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

  Scenario: Reading the surface reports an active API key its Identity names as not blocking it
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the surface reports API key "alpha" as "active", which does not block the surface

  Scenario Outline: Reading the surface reports a revoked or deleted API key its Identity names as blocking it
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the operator has <key change> API key "alpha"
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the surface reports API key "alpha" as "<status>", which blocks the surface

    Examples:
      | key change | status  |
      | revoked    | revoked |
      | deleted    | missing |

  Scenario Outline: Reading a surface stored naming another surface's API key reports whether it blocks the surface
    Given the gateway <rule mode> the credential rule "tenant_credential_isolation"
    And surface "other" was stored with an API key "delta"
    And the surface was stored with its protected Identity taking its DID from API key "delta"
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the surface reports API key "delta" as "unavailable", which <effect> the surface

    Examples:
      | rule mode     | effect         |
      | enforces      | blocks         |
      | only warns on | does not block |

  Scenario: A surface stored naming another surface's API key serves when tenant credential isolation only warns
    Given the gateway only warns on the credential rule "tenant_credential_isolation"
    And surface "other" was stored with an API key "delta"
    And the surface was stored with its protected Identity taking its DID from API key "delta"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received a forwarded request
    And the gateway log has a warning containing "provider_key_tenant"

  Scenario: A surface stored naming another surface's API key is out of service when tenant credential isolation is enforced
    Given the gateway enforces the credential rule "tenant_credential_isolation"
    And surface "other" was stored with an API key "delta"
    And the surface was stored with its protected Identity taking its DID from API key "delta"
    When the caller sends a request to the surface
    Then the response status is 503
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "provider_key_tenant"

  Scenario: A surface naming its own API key serves while another API key folder fails to load
    Given API key "foxtrot" of surface "unreadable" sits in a key folder that fails to load
    And the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: A surface naming an API key id no loaded key folder holds is out of service while a key folder fails to load
    Given API key "foxtrot" of surface "unreadable" sits in a key folder that fails to load
    And the surface was stored with its protected Identity taking its DID from API key "foxtrot"
    When the caller sends a request to the surface
    Then the response status is 503
    And managed agent "bravo" was not called
    And the gateway log has a warning containing "reason=api_key_store_unavailable"

  Scenario: A save through one gateway node cannot add an API key another node revoked
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And the surface has an API key "charlie"
    And another node of the gateway shares its storage
    And the operator has revoked API key "charlie" through the other node
    When the operator saves the surface with its protected Identity taking its DID from API key "charlie"
    Then the admin API response status is 400
    And the admin API error response mentions "is revoked"
    And the stored surface's protected Identity takes its DID from API key "alpha"

  Scenario: Reading the surface through one gateway node reports an API key another node revoked
    Given the surface has an API key "alpha"
    And the surface's protected Identity takes its DID from API key "alpha"
    And another node of the gateway shares its storage
    And the operator has revoked API key "alpha" through the other node
    When the operator reads the surface through the admin API
    Then the surface lookup response status is 200
    And the surface reports API key "alpha" as "revoked", which blocks the surface

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

  Scenario: A new surface can take the id of a deleted surface once its kept API keys are deleted
    Given the surface has an API key "alpha"
    And the operator has deleted the surface
    And the operator has deleted API key "alpha"
    When the operator creates a surface with the deleted surface's id
    Then the admin API response status is 201
    And a surface with the deleted surface's id is stored

  Scenario: Starting the gateway revokes the active API key of a surface that no longer exists
    Given an active API key "echo", created a day ago, belongs to surface "gone", which no longer exists
    And the gateway logs its audit events
    When the gateway starts
    Then the operator reads API key "echo" as revoked, with its surface deleted
    And the gateway log records API key "echo" revoked by "surface-delete"

  Scenario: Starting the gateway keeps the API key an API Key Provider names
    Given the surface requires "API Key Provider" source authentication
    And the surface's API Key Provider accepts API key "golf", created a day ago
    When the gateway starts
    Then the operator reads API key "golf" as active

  Scenario: A gateway starting in Standby keeps the active API key of a surface that no longer exists
    Given an active API key "echo", created a day ago, belongs to surface "gone", which no longer exists
    And the gateway runs in Standby
    When the gateway starts
    Then the operator reads API key "echo" as active

  Scenario: A Standby gateway that becomes Active revokes the active API key of a surface that no longer exists
    Given an active API key "echo", created a day ago, belongs to surface "gone", which no longer exists
    And the gateway runs in Standby
    And the gateway logs its audit events
    When the gateway becomes Active
    Then the operator reads API key "echo" as revoked, with its surface deleted
    And the gateway log records API key "echo" revoked by "surface-delete"
