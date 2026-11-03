Feature: JWT Bearer credential providers
  A JWT Bearer credential provider names the subject its grant is issued for. The admin API
  refuses to save one without a subject, every assertion the gateway signs carries that subject
  and an identifier of its own, a stored provider without a subject is named at startup, and each
  token request sent to a token endpoint is counted by its outcome.

  Scenario: A JWT Bearer provider without a subject is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator creates the JWT Bearer provider "no-subject" using the secret "bdd-signing-key" without a subject
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And no credential provider "no-subject" is stored

  Scenario: A JWT Bearer provider with a blank subject is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator creates the JWT Bearer provider "blank-subject" using the secret "bdd-signing-key" with subject "   "
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And no credential provider "blank-subject" is stored

  Scenario: A JWT Bearer provider with a subject is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator creates the JWT Bearer provider "with-subject" using the secret "bdd-signing-key" with subject "svc@example.com"
    Then the admin API response status is 201
    And the credential provider "with-subject" is stored

  Scenario: Every assertion carries the subject and a jti of its own
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a JWT Bearer provider
    And the provider's JWT subject is "svc@example.com"
    And the caller has sent a request to the surface and received status 200
    And the operator has changed the credential provider's scope to "bdd-new-scope"
    When the caller sends a request to the surface
    Then the response status is 200
    And the target's credential provider received 2 token requests
    And every JWT Bearer assertion the target's credential provider received has subject "svc@example.com"
    And no two JWT Bearer assertions the target's credential provider received share a jti

  Scenario: The startup report names a stored JWT Bearer provider without a subject
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a JWT Bearer provider
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report names the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject" in warn mode

  Scenario: The startup report stays quiet about a JWT Bearer provider with a subject
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a JWT Bearer provider
    And the provider's JWT subject is "svc@example.com"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the gateway log has no warning containing "rule=\"jwt_subject\""

  Scenario: An accepted token request is counted as a success
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    When the caller sends a request to the surface
    Then the response status is 200
    And the token request metric counts 1 "success" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric is labelled only by provider type and outcome

  Scenario: A JWT Bearer token request is counted under its provider type
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a JWT Bearer provider
    When the caller sends a request to the surface
    Then the response status is 200
    And the token request metric counts 1 "success" request for provider type "oauth2_jwt_bearer"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: A refused token request is counted as refused
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    And the target's credential provider is refusing token requests
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"
    And the token request metric is labelled only by provider type and outcome

  Scenario: A token request that outlasts the timeout is counted as a timeout
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    And the gateway gives a token request 1 second before it gives up
    And the target's credential provider answers token requests only after 3000 ms
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "timeout" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: An answer without an access token is counted as an invalid response
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    And the target's credential provider answers token requests with no access token
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "invalid_response" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: A request refused before it reaches the token endpoint is not counted
    Given an A2A surface targeting managed agent "bravo"
    And the surface authenticates its target with a client credentials provider
    And the target's credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the response status is 502
    And the target's credential provider received 0 token requests
    And the token request metric counts no requests
