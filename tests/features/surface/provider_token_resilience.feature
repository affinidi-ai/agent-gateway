Feature: Credential provider token resilience
  The gateway asks a credential provider for a token once per need. A provider that
  fails is not asked again until a backoff has passed, concurrent callers share one
  token request, a slow provider is cut off at the configured timeout, and a change
  to the provider or to a secret it uses makes the next request ask for a new token.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the gateway keeps its log of warnings

  Scenario: A refused token request holds back the next request
    Given the credential provider is refusing token requests
    And the caller has sent a request to the surface and received status 502
    When the caller sends a request to the surface
    Then the response status is 502
    And managed agent "bravo" was not called
    And the credential provider received 1 token request
    And the token request metric counts 1 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: The next request asks for a token again once the backoff has passed
    Given the credential provider is refusing token requests
    And the caller has sent a request to the surface and received status 502
    And the credential provider accepts token requests
    And the caller has waited 2 seconds
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 2 token requests

  Scenario: Concurrent callers share one token request
    Given the credential provider answers token requests only after 1000 ms
    When 8 callers send a request to the surface at the same time
    Then the response status is 200
    And managed agent "bravo" received exactly 8 requests
    And the credential provider received 1 token request

  Scenario: A token request slower than the configured timeout fails
    Given the gateway gives a token request 1 second before it gives up
    And the credential provider answers token requests only after 3000 ms
    When the caller sends a request to the surface
    Then the response status is 502
    And managed agent "bravo" was not called
    And the credential provider received 1 token request
    And the token request metric counts 1 "timeout" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: Editing the provider asks for a new token
    Given the caller has sent a request to the surface and received status 200
    And the operator has changed the credential provider's scope to "bdd-new-scope"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And the credential provider received a client credentials grant from client "bdd-target-client" for scope "https://www.googleapis.com/auth/cloud-platform"
    And the credential provider's latest token request asks for scope "bdd-new-scope"

  Scenario: Replacing a secret the provider uses asks for a new token
    Given the caller has sent a request to the surface and received status 200
    And the operator has replaced the provider's client secret with "bdd-rotated-client-secret-value"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And the credential provider's latest token request carries client secret "bdd-rotated-client-secret-value"

  Scenario: A service account JSON key file signs the JWT Bearer grant
    Given the gateway authenticates to the managed agent with a JWT Bearer provider
    And the provider's signing key is a service account JSON key file
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received a JWT Bearer grant signed with key id "bdd-service-account-key-id"

  Scenario: Only the OAuth error code of a refused token request is logged
    Given the credential provider refuses token requests with error "invalid_client" and description "bdd-echoed-secret-marker"
    When the caller sends a request to the surface
    Then the response status is 502
    And the gateway log has a warning containing "invalid_client"
    And the gateway log does not contain "bdd-echoed-secret-marker"
    And the response body does not contain "bdd-echoed-secret-marker"
    And the delegation audit trail has no record containing "bdd-echoed-secret-marker"
