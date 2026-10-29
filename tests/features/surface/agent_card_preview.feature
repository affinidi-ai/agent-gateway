Feature: Agent card preview
  An operator compares the agent card a managed agent publishes with the card
  the gateway serves for the surface, and sees how the gateway's fetch of the
  managed agent's card went. A failed fetch is reported by its cause and HTTP
  status, and the preview still shows the card the gateway serves, or none when
  the gateway has served none yet. The preview names how Target Authentication
  went on the fetch but never the credential. A read soon after a fetch answers
  from that fetch, while a refresh always fetches again. Reading the preview
  needs permission to view surfaces and refreshing it needs permission to edit
  them. A surface of another tenant is not found. The preview is not a caller
  request, so it records no caller refusal or source authentication failure,
  even when the card route records one for the same failure.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" publishes a v1.0 agent card with its own security

  Scenario: The preview shows the managed agent's card beside the card the gateway serves
    Given the surface requires "JWT Bearer" source authentication
    And the surface publishes the authorization server of its source authentication
    And the surface requires scopes "agent.invoke"
    And the caller has fetched the agent card
    When the operator reads the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a successful fetch
    And the agent card preview shows the card managed agent "bravo" publishes
    And the agent card preview shows the card the caller was served
    And the agent card preview reports the declaration outcome "declare"

  Scenario: A failed fetch is reported by its cause while the served card is still shown
    Given the caller has fetched the agent card
    And managed agent "bravo" is failing with status 500
    When the operator refreshes the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a failed fetch with cause "upstream_error" and HTTP status 500
    And the agent card preview shows no card from managed agent "bravo"
    And the agent card preview shows the card the caller was served

  Scenario: A failed fetch before the gateway has served a card shows no served card
    Given managed agent "bravo" is failing with status 500
    When the operator reads the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a failed fetch with cause "upstream_error" and HTTP status 500
    And the agent card preview shows no served card

  Scenario: A managed agent that refuses the gateway's Target credential is reported as a failed sign-in
    Given the surface injects target authentication from secret "bdd-target-api-key" with value "bdd-target-secret" as header "x-target-api-key"
    And managed agent "bravo" is failing with status 401
    When the operator refreshes the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a failed fetch with cause "auth_failed" and HTTP status 401
    And the agent card preview reports the Target credential as "sent"
    And the agent card preview does not reveal the Target credential from secret "bdd-target-api-key" with value "bdd-target-secret"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: Refreshing the preview of a surface whose Target Authentication fails records no caller refusal
    Given the VP Audit Log keeps every audit event
    And the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "reject"
    When the operator refreshes the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a failed fetch with cause "auth_failed" and no HTTP status
    And the agent card preview reports the Target credential as "failed"
    And managed agent "bravo" was not called
    And the VP Audit Log records no caller refusal or source authentication failure

  Scenario: The same Target Authentication failure on the card route is recorded as a caller refusal
    Given the VP Audit Log keeps every audit event
    And the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "reject"
    When the caller fetches the agent card
    Then the response status is 502
    And the VP Audit Log records a request refusal for "a Target Authentication failure"
    And managed agent "bravo" was not called

  Scenario: A refresh after the managed agent recovers reports a successful fetch
    Given managed agent "bravo" is failing with status 401
    And the operator has read the agent card preview of the surface
    And managed agent "bravo" publishes a v1.0 agent card with its own security
    When the operator refreshes the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a successful fetch
    And the agent card preview shows the card managed agent "bravo" publishes

  Scenario: A read soon after a fetch answers from that fetch
    Given managed agent "bravo" is failing with status 401
    And the operator has read the agent card preview of the surface
    And managed agent "bravo" publishes a v1.0 agent card with its own security
    When the operator reads the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview answers from the earlier fetch
    And the agent card preview reports a failed fetch with cause "needs_token" and HTTP status 401

  Scenario: An operator who may view surfaces reads the preview
    Given operator "uma" has the "user" role
    When operator "uma" reads the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview reports a successful fetch

  Scenario: Refreshing the preview needs permission to edit surfaces
    Given operator "uma" has the "user" role
    When operator "uma" refreshes the agent card preview of the surface
    Then the admin API response status is 403
    And the admin API response reveals nothing of the agent card

  Scenario: The preview of another tenant's surface is not found
    Given the surface belongs to tenant "tenant-b"
    And the operator has issued an access token for tenant "tenant-a"
    When the holder of the access token for tenant "tenant-a" reads the agent card preview of the surface
    Then the admin API response status is 404
    And the admin API response reveals nothing of the agent card

  Scenario: Another tenant cannot refresh the preview
    Given the surface belongs to tenant "tenant-b"
    And the operator has issued an access token for tenant "tenant-a"
    When the holder of the access token for tenant "tenant-a" refreshes the agent card preview of the surface
    Then the admin API response status is 404
    And the admin API response reveals nothing of the agent card

  Scenario: A tenant reads the preview of its own surface
    Given the surface belongs to tenant "tenant-b"
    And the operator has issued an access token for tenant "tenant-b"
    When the holder of the access token for tenant "tenant-b" reads the agent card preview of the surface
    Then the admin API response status is 200
    And the agent card preview shows the card managed agent "bravo" publishes
