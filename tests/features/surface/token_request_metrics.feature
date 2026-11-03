Feature: Credential provider token request metrics
  Each service token request the gateway sends to a credential provider's token endpoint is
  counted by its outcome and provider type. A token request that is not sent is not counted.
  The timeout, refusal and not-sent outcomes are asserted in the token resilience and credential
  policy features, next to the scenarios that cause them.

  Scenario: An accepted token request is counted as a success
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    When the caller sends a request to the surface
    Then the response status is 200
    And the token request metric counts 1 "success" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric is labelled only by provider type and outcome

  Scenario: A JWT Bearer token request is counted under its provider type
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    When the caller sends a request to the surface
    Then the response status is 200
    And the token request metric counts 1 "success" request for provider type "oauth2_jwt_bearer"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: A token request that gets no connection is counted as refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider's token endpoint is not listening
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: An answer without an access token is counted as an invalid response
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider answers token requests with no access token
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "invalid_response" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"
