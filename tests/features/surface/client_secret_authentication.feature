Feature: Client secret authentication
  A client credentials provider, and an authorization code provider on its code exchange and
  every refresh, sends its client ID and secret in the form body unless its client
  authentication is HTTP Basic, which every token endpoint must accept and some require.
  A provider stored without a client authentication keeps sending them in the form body. The
  admin API stores HTTP Basic on a client credentials provider and refuses a public client there,
  since such a provider always sends its client secret.

  Scenario: A client credentials provider that authenticates by HTTP Basic sends no client field in its form body
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider authenticates its client with "HTTP Basic"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider's latest token request carries HTTP Basic credentials for client "bdd-target-client" and secret "bdd-target-client-secret-value"
    And the credential provider's latest token request has no client ID or secret in its form body

  Scenario: A client credentials provider stored without a client authentication sends its client ID and secret in the form body
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider's latest token request carries client ID "bdd-target-client"
    And the credential provider's latest token request carries client secret "bdd-target-client-secret-value"
    And the credential provider's latest token request carries no HTTP Basic credentials

  Scenario: An authorization code provider that authenticates by HTTP Basic exchanges a code with no client field in its form body
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from OAuth provider "calendar"
    And OAuth provider "calendar" authenticates its client with "HTTP Basic"
    And caller "alice" has started OAuth consent for provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    When OAuth provider "calendar" redirects the caller back with a valid authorization code
    Then the OAuth callback response status is 200
    And OAuth provider "calendar" received the authorization code exchange
    And OAuth provider "calendar"'s latest token request carries HTTP Basic credentials for client "bdd-client-id" and secret "bdd-client-secret"
    And OAuth provider "calendar"'s latest token request has no client ID or secret in its form body

  Scenario: An authorization code provider that authenticates by HTTP Basic refreshes a credential with no client field in its form body
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from OAuth provider "calendar"
    And OAuth provider "calendar" authenticates its client with "HTTP Basic"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's delegated credentials have expired
    And OAuth provider "calendar" is ready to refresh delegated credentials
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And OAuth provider "calendar" received the refresh request
    And OAuth provider "calendar"'s latest token request carries HTTP Basic credentials for client "bdd-client-id" and secret "bdd-client-secret"
    And OAuth provider "calendar"'s latest token request has no client ID or secret in its form body

  Scenario: A client credentials provider that authenticates by HTTP Basic is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "bdd-client-id"
    And the appliance holds the secret "bdd-client-secret"
    When the operator creates the credential provider "m2m" with token endpoint "https://192.0.2.1/token" using secrets "bdd-client-id" and "bdd-client-secret", authenticating its client with "HTTP Basic"
    Then the admin API response status is 201
    And the credential provider "m2m" is stored

  Scenario: A public client is refused on a client credentials provider and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "bdd-client-id"
    And the appliance holds the secret "bdd-client-secret"
    When the operator creates the credential provider "m2m-public" with token endpoint "https://192.0.2.1/token" using secrets "bdd-client-id" and "bdd-client-secret", authenticating its client with "the client ID only"
    Then the admin API response status is 400
    And the admin API error response mentions "client_authentication none is only for oauth2_jwt_bearer providers"
    And no credential provider "m2m-public" is stored
