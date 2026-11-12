Feature: Consent confirmation
  A credential provider with consent confirmation has the person sign in at the callers'
  identity provider before the gateway sends them to the OAuth provider, and refuses anyone
  but the caller the consent link was minted for.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the VP Audit Log keeps every audit event
    And the surface requires delegated credentials from OAuth provider "calendar"

  Scenario: A JWT caller's consent start sends the browser to the identity provider before the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    When caller "alice" confirms the consent start page for provider "calendar"
    Then the consent start response status is 302
    And the consent start response sends the browser to the identity provider
    And the consent start response asks the identity provider to send the browser back to the consent confirmation callback

  Scenario: A caller who signs in at the identity provider as themselves is sent on to the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has signed in at the identity provider as "alice"
    When the identity provider sends the caller back to the gateway
    Then the OAuth callback response status is 302
    And the OAuth callback response sends the browser to OAuth provider "calendar"

  Scenario: Delegated credentials obtained after consent confirmation are injected into the MCP server request
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has signed in at the identity provider as "alice"
    And the identity provider has sent the caller back to the gateway
    And OAuth provider "calendar" has sent the caller back with a valid authorization code
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"

  Scenario: Another person who signs in at the identity provider is refused before the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has signed in at the identity provider as "bob"
    When the identity provider sends the caller back to the gateway
    Then the OAuth callback response status is 403
    And the OAuth callback response shows an authorization failure page
    And the OAuth callback response does not send the browser to OAuth provider "calendar"
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "consent_identity_mismatch"
    And the delegation audit trail has no event "consent_granted" for OAuth provider "calendar"

  Scenario: A sign-in whose ID token lacks the sign-in's nonce is refused before the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    And the identity provider issues ID tokens without the nonce of the sign-in
    And caller "alice" has signed in at the identity provider as "alice"
    When the identity provider sends the caller back to the gateway
    Then the OAuth callback response status is 403
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "consent_identity_missing"

  Scenario: A sign-in whose surface was deleted meanwhile is refused before the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has signed in at the identity provider as "alice"
    And the operator has deleted the surface the consent link was minted on
    When the identity provider sends the caller back to the gateway
    Then the OAuth callback response status is 400
    And the OAuth callback response shows an authorization failure page
    And OAuth provider "calendar" was not asked to exchange an authorization code
    And the delegation audit trail records a refused consent for OAuth provider "calendar" with reason "consent_state_invalid"

  Scenario: A JWT verification strategy that confirms a provider's callers cannot be deleted
    Given OAuth provider "calendar" confirms its caller at the identity provider
    When the operator deletes the JWT verification strategy that confirms the callers
    Then the admin API response status is 409
    And the admin API error response mentions "credential providers"
    And the JWT verification strategy that confirms the callers is still listed

  Scenario: An issuer a confirming provider would refuse cannot be saved on its strategy
    Given OAuth provider "calendar" confirms its caller at the identity provider
    When the operator changes the issuer of the JWT verification strategy that confirms the callers to an Entra issuer
    Then the admin API response status is 409
    And the admin API error response mentions "expected_issuer"
    And the JWT verification strategy that confirms the callers keeps its issuer

  Scenario: A JWT caller's consent start goes straight to the OAuth provider without consent confirmation
    Given the callers' identity provider is available
    And caller "alice" has started OAuth consent for provider "calendar"
    When caller "alice" confirms the consent start page for provider "calendar"
    Then the consent start response status is 302
    And the consent start response sends the browser to OAuth provider "calendar"

  Scenario: An API key caller's consent start goes straight to the OAuth provider with consent confirmation
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And OAuth provider "calendar" confirms its caller at the identity provider
    And caller "alice" has started OAuth consent for provider "calendar" with a valid API key
    When caller "alice" confirms the consent start page for provider "calendar"
    Then the consent start response status is 302
    And the consent start response sends the browser to OAuth provider "calendar"

  Scenario: An API key caller gets no consent link from a provider that requires consent confirmation
    Given the surface accepts "JWT Bearer" and "API Key" source authentication
    And OAuth provider "calendar" refuses a consent link to a caller it cannot confirm
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid API key
    Then the response status is 503
    And the MCP response is a JSON-RPC error with code -32603
    And MCP server "bravo" was not called

  Scenario: A JWT caller's consent start is still confirmed by a provider that requires consent confirmation
    Given OAuth provider "calendar" refuses a consent link to a caller it cannot confirm
    And caller "alice" has started OAuth consent for provider "calendar"
    When caller "alice" confirms the consent start page for provider "calendar"
    Then the consent start response status is 302
    And the consent start response sends the browser to the identity provider

  Scenario: Consent confirmation cannot be saved while the identity hash pepper is unset
    When the operator creates the authorization code provider "mail" with consent confirmation
    Then the admin API response status is 400
    And the admin API error response mentions "AG_IDENTITY_HASH_PEPPER"
    And no credential provider "mail" is stored
