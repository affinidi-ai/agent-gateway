Feature: JWT Bearer client authentication
  A JWT Bearer credential provider sends no client identity with its grant unless it sets a
  client authentication. A public client sends its client ID. A confidential client sends its
  client ID and secret by HTTP Basic or in the form body. The admin API refuses a client
  authentication that lacks the client references it sends, and the gateway never logs the
  client secret.

  Scenario: A JWT Bearer provider without a client authentication sends no client identity
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores a client ID and a client secret but sets no client authentication
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider's latest token request has no client ID or secret in its form body
    And the credential provider's latest token request carries no HTTP Basic credentials

  Scenario: A public client sends its client ID and no secret
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the client ID only"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider received a JWT Bearer grant signed with the provider key
    And the credential provider's latest token request carries client ID "bdd-target-client"
    And the credential provider's latest token request carries no HTTP Basic credentials

  Scenario: A confidential client sends its client ID and secret by HTTP Basic
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "HTTP Basic"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider received a JWT Bearer grant signed with the provider key
    And the credential provider's latest token request carries HTTP Basic credentials for client "bdd-target-client" and secret "bdd-target-client-secret-value"
    And the credential provider's latest token request has no client ID or secret in its form body

  Scenario: A confidential client sends its client ID and secret in the form body
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the form body"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider received a JWT Bearer grant signed with the provider key
    And the credential provider's latest token request carries client ID "bdd-target-client"
    And the credential provider's latest token request carries client secret "bdd-target-client-secret-value"
    And the credential provider's latest token request carries no HTTP Basic credentials

  Scenario: A client authentication also asks for the scopes in the form body
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the client ID only"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And the credential provider's latest token request asks for scope "https://www.googleapis.com/auth/cloud-platform"

  Scenario: Replacing the client secret makes the gateway ask for a new token
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the form body"
    And the caller has sent a request to the surface and received status 200
    And the operator has replaced the provider's client secret with "bdd-rotated-client-secret-value"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And the credential provider's latest token request carries client secret "bdd-rotated-client-secret-value"

  Scenario: A refused grant leaves no client secret in the gateway log
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "HTTP Basic"
    And the credential provider is refusing token requests
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 1 token request
    And the credential provider's latest token request carries HTTP Basic credentials for client "bdd-target-client" and secret "bdd-target-client-secret-value"
    And the gateway log shows no credential provider secret or token

  Scenario: A JWT Bearer provider with a client authentication and its client references is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    And the appliance holds the secret "bdd-client-id"
    And the appliance holds the secret "bdd-client-secret"
    When the operator creates the JWT Bearer provider "with-basic" using the secret "bdd-signing-key" with subject "svc@example.com", authenticating its client with "HTTP Basic" with the client ID secret "bdd-client-id" and the client secret "bdd-client-secret"
    Then the admin API response status is 201
    And the credential provider "with-basic" is stored

  Scenario Outline: A client authentication that sends a secret is refused without the client secret and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    And the appliance holds the secret "bdd-client-id"
    When the operator creates the JWT Bearer provider "<provider>" using the secret "bdd-signing-key" with subject "svc@example.com", authenticating its client with "<authentication>" with the client ID secret "bdd-client-id"
    Then the admin API response status is 400
    And the admin API error response mentions "client_secret_secret_ref is required"
    And no credential provider "<provider>" is stored

    Examples:
      | provider   | authentication |
      | basic-only | HTTP Basic     |
      | form-only  | the form body  |

  Scenario: A public client is refused a client secret and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    And the appliance holds the secret "bdd-client-id"
    And the appliance holds the secret "bdd-client-secret"
    When the operator creates the JWT Bearer provider "public-with-secret" using the secret "bdd-signing-key" with subject "svc@example.com", authenticating its client with "the client ID only" with the client ID secret "bdd-client-id" and the client secret "bdd-client-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "client_secret_secret_ref is not allowed"
    And no credential provider "public-with-secret" is stored

  Scenario: A client authentication is refused on a provider of another type and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "bdd-client-id"
    And the appliance holds the secret "bdd-client-secret"
    When the operator creates the credential provider "m2m" with token endpoint "https://192.0.2.1/token" using secrets "bdd-client-id" and "bdd-client-secret", authenticating its client with "HTTP Basic"
    Then the admin API response status is 400
    And the admin API error response mentions "only for oauth2_jwt_bearer"
    And no credential provider "m2m" is stored

  Scenario: Clearing the client authentication of a stored provider sends a client-less grant
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the form body"
    And the caller has sent a request to the surface and received status 200
    And the operator has cleared the credential provider's client authentication
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And the credential provider's latest token request has no client ID or secret in its form body
    And the credential provider's latest token request carries no HTTP Basic credentials

  Scenario: A provider with a plain http token endpoint is refused a client authentication that sends its client secret
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores a client ID and a client secret but sets no client authentication
    And the credential provider has a plain http token endpoint
    When the operator changes the credential provider's client authentication to "HTTP Basic"
    Then the admin API response status is 400
    And the admin API error response mentions "token_endpoint must be an https URL"
    And the stored credential provider has no client authentication

  Scenario: A stored provider is refused a public client authentication while it stores a client secret
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "HTTP Basic"
    When the operator changes the credential provider's client authentication to "the client ID only"
    Then the admin API response status is 400
    And the admin API error response mentions "client_secret_secret_ref is not allowed"
    And the stored credential provider has the client authentication "HTTP Basic"

  Scenario: Clearing a provider's client authentication and client ID releases the client ID secret
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "the client ID only"
    And the operator has cleared the credential provider's client authentication and client ID
    When the operator deletes the secret "bdd-target-client-id"
    Then the admin API response status is 204
    And no secret "bdd-target-client-id" is stored

  Scenario: The credential provider list shows a provider's client authentication
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider authenticates its client with "HTTP Basic"
    When the operator lists the credential providers
    Then the credential provider list shows the client authentication "HTTP Basic" for provider "bdd-target-provider"
