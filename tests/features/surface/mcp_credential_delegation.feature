Feature: MCP credential delegation
  The gateway obtains, stores, and injects caller-delegated credentials for MCP
  tool calls without exposing delegated secrets to the caller.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the VP Audit Log keeps every audit event

  Scenario: Missing delegated credentials ask the caller for consent before the MCP server is reached
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the surface has an explicit inbound identity slot for MCP
    And caller "alice" has no delegated credentials for OAuth provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token and a valid inbound identity payload
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And the consent required error names neither the caller's identity hash nor the managed agent's DID
    And the response includes an authorization URL for OAuth provider "calendar"
    And the response includes delegated credential scopes "calendar.read calendar.write"
    And the delegation audit trail contains event "consent_required" for OAuth provider "calendar"
    And MCP server "bravo" was not called

  Scenario: A delegated credential that cannot be resolved refuses the MCP tool call before the MCP server is reached
    Given the surface requires delegated credentials from credential provider "retired", which the gateway does not have
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 503
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

  Scenario: OAuth consent callback exchanges an authorization code and records the consent grant
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the surface has an explicit inbound identity slot for MCP
    And caller "alice" has started OAuth consent for provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    When OAuth provider "calendar" redirects the caller back with a valid authorization code
    Then the OAuth callback response status is 200
    And OAuth provider "calendar" received the authorization code exchange
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"

  Scenario: OAuth consent completes at a callback path ending in the id the gateway gave the provider
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And OAuth provider "calendar" has a callback path ending in the id the gateway gave it
    And the surface has an explicit inbound identity slot for MCP
    And caller "alice" has started OAuth consent for provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    When OAuth provider "calendar" redirects the caller back with a valid authorization code
    Then the OAuth callback response status is 200
    And OAuth provider "calendar" received the authorization code exchange
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"

  Scenario Outline: OAuth callback shows an authorization failure page without exchanging credentials
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    When OAuth provider "calendar" redirects the caller back <callback condition>
    Then the OAuth callback response status is 400
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code

    Examples:
      | callback condition                 |
      | with an invalid state parameter    |
      | with an expired state parameter    |
      | with a forged state parameter      |
      | with a provider error              |

  Scenario: OAuth callback refuses a state that was already used
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When OAuth provider "calendar" redirects the caller back again with the same state
    Then the OAuth callback response status is 400
    And the OAuth callback response shows an authorization failure page

  Scenario: OAuth callback opened in another browser is refused without exchanging credentials
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has confirmed the consent start page for provider "calendar"
    When OAuth provider "calendar" redirects another browser back with a valid authorization code
    Then the OAuth callback response status is 403
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "browser_binding_mismatch"

  Scenario: OAuth callback with another issuer is refused when the provider records its issuer
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And OAuth provider "calendar" records authorization response issuer "https://calendar.example"
    And caller "alice" has started OAuth consent for provider "calendar"
    When OAuth provider "calendar" redirects the caller back with a valid authorization code and issuer "https://other.example"
    Then the OAuth callback response status is 400
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "iss_mismatch"

  Scenario: OAuth callback at another provider's callback URL is refused
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the gateway has OAuth provider "mail"
    And caller "alice" has started OAuth consent for provider "calendar"
    When OAuth provider "calendar" redirects the caller back to the callback URL of OAuth provider "mail"
    Then the OAuth callback response status is 400
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "mail" with reason "consent_provider_mismatch"

  Scenario: A consent start posted from another site is refused and does not reach the OAuth provider
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    When a page on another site confirms the consent start page for OAuth provider "calendar"
    Then the consent start response status is 403
    And the consent start response shows an authorization failure page
    And the consent start response does not send the browser to OAuth provider "calendar"
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "cross_site_consent_start"

  Scenario: Delegated credentials are injected into the MCP server request after consent
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"
    And the delegation audit trail contains event "token_injected" for OAuth provider "calendar"
    And the delegation audit trail does not expose delegated credential secrets
    And the MCP response does not expose delegated credential secrets

  Scenario: Stored delegated credentials are reused on a later MCP call without asking for consent
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And caller "alice" has completed an earlier MCP tool call using those delegated credentials
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received the later MCP tool call
    And the MCP response does not ask caller "alice" for consent
    And the delegation audit trail contains event "token_injected" for OAuth provider "calendar" on the later MCP tool call

  Scenario: Delegated credentials are scoped to the authenticated caller
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "bob" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And MCP server "bravo" was not called

  Scenario: Delegated credentials are scoped to the caller Agent DID
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the surface has an explicit inbound identity slot for MCP
    And caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token and inbound identity field "softwareInfo.name" set to "researcher"
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And MCP server "bravo" was not called

  Scenario: An expired refreshable delegated credential is refreshed and injected
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's delegated credentials have expired
    And OAuth provider "calendar" is ready to refresh delegated credentials
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And OAuth provider "calendar" received the refresh request
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"
    And the delegation audit trail contains event "token_refreshed" for OAuth provider "calendar"
    And the delegation audit trail contains event "token_injected" for OAuth provider "calendar"
    And the delegation audit trail does not expose delegated credential secrets
    And the MCP response does not expose delegated credential secrets

  Scenario: A credential whose refresh fails asks the caller to consent again
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's delegated credentials have expired
    And OAuth provider "calendar" rejects delegated credential refresh
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And MCP server "bravo" was not called

  Scenario: An unmatched MCP tool call passes through without delegated credentials
    Given the surface requires delegated credentials from OAuth provider "calendar" only for MCP tool "schedule_meeting"
    When caller "alice" invokes MCP tool "get_news" with a valid token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" did not receive delegated credential for OAuth provider "calendar"

  Scenario: A per-tool credential requirement injects credentials for the matched MCP tool call
    Given the surface requires delegated credentials from OAuth provider "calendar" only for MCP tool "schedule_meeting"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"

  Scenario: An API-key credential provider injects the delegated secret without a consent round-trip
    Given the surface requires delegated credentials from API-key provider "maps"
    When caller "alice" invokes MCP tool "lookup_place" with a valid token
    Then the response status is 200
    And MCP server "bravo" received delegated credential for API-key provider "maps"
    And the MCP response does not ask caller "alice" for consent

  Scenario: A delegated credential injects as a custom header when configured
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the surface injects delegated credentials from OAuth provider "calendar" as header "x-calendar-token"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received header "x-calendar-token" with delegated credential from OAuth provider "calendar"
    And MCP server "bravo" did not receive MCP _meta key "calendar"

  Scenario: A delegated credential injects into MCP metadata when configured
    Given the surface requires delegated credentials from OAuth provider "calendar"
    And the surface injects delegated credentials from OAuth provider "calendar" into MCP metadata key "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received MCP _meta key "calendar" with delegated credential from OAuth provider "calendar"
    And MCP server "bravo" did not receive header "x-calendar-token"
