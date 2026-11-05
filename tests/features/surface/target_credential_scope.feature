Feature: Target credential scope on the direct path
  The gateway sends the Target credential only to URLs under the Target endpoint. A
  request whose path climbs out of the Target base path, written plainly, percent-encoded
  or as an ambiguous segment, is refused before anything reaches the Target. An encoded
  slash stays encoded. A caller header named like the Target credential header never
  reaches the Target, and a redirect from the Target is returned to the caller instead of
  being followed with the credential. A token the Access Point forwards for a caller it
  verified goes beside the Target credential. A stored Target credential whose header is one
  the gateway may not set is never sent: the request is refused, or forwarded without it
  when its fallback is passthrough.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface's Target endpoint has the base path "/base"
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"

  Scenario: A request to the Target base path carries the Target credential
    When the caller sends a request to the surface path "/smoke" exactly as written
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/base"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A request below the Target base path carries the Target credential
    When the caller sends a request to the surface path "/smoke/rpc" exactly as written
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/base/rpc"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: An encoded slash below the Target base path stays encoded
    When the caller sends a request to the surface path "/smoke/a%2Fb" exactly as written
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/base/a%2Fb"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario Outline: A request whose path leaves the Target base path is refused before the Target
    When the caller sends a request to the surface path "<path>" exactly as written
    Then the response status is 502
    And the response mentions "Target authentication failed"
    And managed agent "bravo" was not called

    Examples:
      | path                    |
      | /smoke/../admin         |
      | /smoke/./../admin       |
      | /smoke/%2e%2e/admin     |
      | /smoke/%2E%2E/admin     |
      | /smoke/..;/admin        |
      | /smoke/..%2Fadmin       |
      | /smoke/..%5Cadmin       |
      | /smoke/%252e%252e/admin |

  Scenario: A stored Target credential in a reserved header is not sent and the request is refused
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "X-Transit-Token"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 502
    And the response mentions "Target authentication failed"
    And managed agent "bravo" was not called
    And the VP Audit Log records a Target credential that was not sent, with outcome "rejected" and no OAuth error

  Scenario: A stored Target credential in a reserved header is left out when fallback is passthrough
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "X-Transit-Token"
    And the gateway's authentication to the managed agent falls back to "passthrough"
    And the VP Audit Log keeps every audit event
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-transit-token"
    And the VP Audit Log records a Target credential that was not sent, with outcome "passthrough" and no OAuth error

  Scenario: A caller header named like the Target credential header is replaced by the Target credential
    When the caller sends a request to the surface with header "X-Target-Api-Key" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A caller header named like the Target credential header is dropped when the credential is not sent
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "passthrough"
    When the caller sends a request to the surface with header "X-TARGET-API-KEY" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: A caller header spelling the Target credential header with underscores is dropped
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "passthrough"
    When the caller sends a request to the surface with header "X_Target_Api_Key" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" did not receive header "x_target_api_key"

  Scenario: The agent card fetch drops a caller header named like the Target credential header when the credential is not sent
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "passthrough"
    When the caller fetches the agent card with header "X-Target-Api-Key" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario Outline: The agent card fetch drops a caller header named like a delegated credential header
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "passthrough"
    And the surface requires delegated credentials from OAuth provider "maps"
    And the surface injects delegated credentials from OAuth provider "maps" as header "x-vendor-token"
    When the caller fetches the agent card with header "<header>" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" did not receive header "<header>"

    Examples:
      | header         |
      | X-Vendor-Token |
      | X_Vendor_Token |

  Scenario: A caller header with another name reaches the Target
    When the caller sends a request to the surface with header "X-Caller-Note" set to "caller-chosen-value"
    Then the response status is 200
    And managed agent "bravo" received header "x-caller-note" with value "caller-chosen-value"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A Target redirect is returned to the caller instead of being followed with the credential
    Given managed agent "bravo" answers every request with a redirect to its path "/elsewhere"
    When the caller sends a request to the surface path "/smoke/rpc" exactly as written
    Then the response status is 302
    And the response header "location" points at path "/elsewhere" of managed agent "bravo"
    And managed agent "bravo" received exactly 1 request
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A JWT Bearer caller's forwarded token goes beside the Target credential when Target source authentication is enforced
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's Access Point forwards the token of a caller its JWT Bearer method verifies to managed agent "bravo"
    And the gateway enforces the credential rule "target_source_auth"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the caller's "authorization" header unchanged
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: An API key caller gets the Target credential and no forwarded credential when Target source authentication is enforced
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And the surface's Access Point forwards the token of a caller its JWT Bearer method verifies to managed agent "bravo"
    And the gateway enforces the credential rule "target_source_auth"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And managed agent "bravo" did not receive header "authorization"
    And managed agent "bravo" did not receive header "x-api-key"
