Feature: JWT Bearer credential providers
  A JWT Bearer credential provider names the subject its grant is issued for. The admin API
  refuses to save one without a subject, every assertion the gateway signs carries that subject
  and an identifier of its own, a stored provider without a subject is named at startup, and each
  token request sent to a token endpoint is counted by its outcome. The gateway writes its startup
  report when it starts, so each report scenario sends one request to be sure it is running.

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

  Scenario: A JWT Bearer provider validated without a subject is refused before any token request
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator validates a JWT Bearer provider using the secret "bdd-signing-key" without a subject
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"

  Scenario: A JWT Bearer provider validated with a subject is accepted
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the signing key "bdd-signing-key"
    When the operator validates a JWT Bearer provider using the secret "bdd-signing-key" with subject "svc@example.com"
    Then the admin API response status is 200

  Scenario: A change to a stored JWT Bearer provider without a subject is refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the operator changes the credential provider's scope to "bdd-new-scope"
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores no subject

  Scenario: A change to a stored JWT Bearer provider that names a subject is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the operator changes the credential provider's scope to "bdd-new-scope" and names the subject "svc@example.com"
    Then the admin API response status is 200
    And the credential provider stores the subject "svc@example.com"

  Scenario: Rotating the signing key of a stored JWT Bearer provider without a subject is refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the appliance holds the signing key "rotated-key"
    When the operator changes the credential provider's signing key to the secret "rotated-key"
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores no subject

  Scenario: Rotating the signing key of a stored JWT Bearer provider that names a subject is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the appliance holds the signing key "rotated-key"
    When the operator changes the credential provider's signing key to the secret "rotated-key" and names the subject "svc@example.com"
    Then the admin API response status is 200
    And the credential provider stores the subject "svc@example.com"

  Scenario: Clearing the subject of a stored JWT Bearer provider is refused and the subject is kept
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    When the operator clears the credential provider's subject
    Then the admin API response status is 400
    And the admin API error response mentions "jwt_subject is required"
    And the credential provider stores the subject "svc@example.com"

  Scenario: A stored JWT Bearer provider without a subject still signs its grant without a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 1 token request
    And no JWT Bearer assertion the credential provider received carries a subject

  Scenario: Every assertion carries the subject and a jti of its own
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    And the caller has sent a request to the surface and received status 200
    And the operator has changed the credential provider's scope to "bdd-new-scope"
    When the caller sends a request to the surface
    Then the response status is 200
    And the credential provider received 2 token requests
    And every JWT Bearer assertion the credential provider received has subject "svc@example.com"
    And no two JWT Bearer assertions the credential provider received share a jti

  Scenario: The startup report names a stored JWT Bearer provider without a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report names the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject" in warn mode

  Scenario: The startup report stays quiet about a JWT Bearer provider with a subject
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider
    And the credential provider stores the JWT subject "svc@example.com"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report does not name the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject"

  Scenario: The subject rule only warns while another credential rule is enforced
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a JWT Bearer provider stored without a subject
    And the gateway enforces the credential rule "token_endpoint_https"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface
    Then the response status is 200
    And the startup report names the credential_provider "bdd-target-provider" as breaking the rule "jwt_subject" in warn mode

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

  Scenario: A refused token request is counted as refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider is refusing token requests
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"
    And the token request metric is labelled only by provider type and outcome

  Scenario: A token request that gets no connection is counted as refused
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider's token endpoint is not listening
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "refused" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: A token request that outlasts the timeout is counted as a timeout
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the gateway gives a token request 1 second before it gives up
    And the credential provider answers token requests only after 3000 ms
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "timeout" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: An answer without an access token is counted as an invalid response
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider answers token requests with no access token
    When the caller sends a request to the surface
    Then the response status is 502
    And the token request metric counts 1 "invalid_response" request for provider type "oauth2_client_credentials"
    And the token request metric counts 0 "success" request for provider type "oauth2_client_credentials"

  Scenario: A token request refused before it is sent is not counted
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider has a plain http token endpoint
    And the gateway enforces the credential rule "token_endpoint_https"
    When the caller sends a request to the surface
    Then the response status is 502
    And the credential provider received 0 token requests
    And the token request metric counts no requests
