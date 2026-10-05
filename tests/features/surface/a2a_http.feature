Feature: A2A HTTP surface forwarding and identity
  The gateway proxies inbound A2A requests through configured
  surfaces to their targets.
  With managed identity enabled, the gateway replaces raw
  agent-identity/v1 extensions with signed agent-identity-credential/v1
  containing a Verifiable Presentation and DID.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: Request is forwarded to the managed agent
    When the caller sends a request to the surface
    Then managed agent "bravo" received the forwarded request
    And managed agent "bravo" received the forwarded request with content type "application/json"
    And the response status is 200
    And the response content type is "application/json"
    And the response body matches managed agent "bravo" response

  Scenario: Managed agent error status reaches the caller unchanged
    Given managed agent "bravo" is failing with status 503
    When the caller sends a request to the surface
    Then the response status is 503
    And the response body matches managed agent "bravo" response
    And managed agent "bravo" received the forwarded request

  Scenario: A2A response from the managed agent has identity credential injected
    Given the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    When the caller sends a request to the surface
    Then managed agent "bravo" received the forwarded request
    And the response status is 200
    And the response contains the credential extension
    And the response does not contain the raw identity extension
    And the response contains a valid Verifiable Presentation

  Scenario: A2A agent card has identity credential injected
    Given the surface has managed identity enabled
    And managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card contains the credential extension
    And the agent card does not contain the raw identity extension
    And the agent card contains a valid Verifiable Presentation

  Scenario: Caller identity is not enforced when only a Server Identity (MA to AP) is configured
    # The surface configures a protected (MA to AP) Server Identity but no
    # inbound (CA to AP) identity element. A caller that happens to include a
    # non-matching agent-identity extension must NOT be validated against the
    # protected schema — the request is forwarded and the protected identity is
    # still resolved from the response. Regression guard.
    Given the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    When the caller sends a request to the surface with a mismatched identity extension
    Then managed agent "bravo" received the forwarded request
    And the response status is 200
    And the response contains the credential extension

  Scenario: Non-schema fields do not affect A2A identity DID
    Given the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    When the caller sends two requests that differ only in non-identity fields
    Then both responses contain the same DID

  Scenario: A2A agent card fetch presents the surface's target credential
    Given the surface injects target authentication from secret "bdd-target-api-key" with value "bdd-target-secret" as header "x-target-api-key"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A caller cannot override or ride along on the credentialed agent card fetch
    Given the surface injects target authentication from secret "bdd-target-api-key" with value "bdd-target-secret" as header "x-target-api-key"
    When the caller fetches the agent card with extra headers
      | x-target-api-key | caller-forged  |
      | cookie           | session=caller |
      | x-forwarded-user | caller-forged  |
      | x-remote-user    | caller-forged  |
      | accept-language  | en-GB          |
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And managed agent "bravo" did not receive header "cookie"
    And managed agent "bravo" did not receive header "x-forwarded-user"
    And managed agent "bravo" did not receive header "x-remote-user"
    And managed agent "bravo" received header "accept-language" with value "en-GB"

  Scenario: The credentialed agent card fetch does not follow a redirect
    Given the surface injects target authentication from secret "bdd-target-api-key" with value "bdd-target-secret" as header "x-target-api-key"
    And managed agent "bravo" redirects its agent card to managed agent "charlie"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_upstream_redirected"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And managed agent "charlie" was not called

  Scenario: A missing target credential fails the agent card when fallback is reject
    Given the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "reject"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And managed agent "bravo" was not called

  Scenario: A missing target credential fetches the agent card without it when fallback is passthrough
    Given the surface injects target authentication from missing secret "bdd-missing-target-secret" as header "x-target-api-key" with fallback "passthrough"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: Without a target credential the agent card fetch forwards caller headers as before
    When the caller fetches the agent card with extra headers
      | cookie | session=caller |
    Then the response status is 200
    And managed agent "bravo" received header "cookie" with value "session=caller"
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: A2A agent card URL points to the gateway, not the Target
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card url points to the gateway listen address
    And the agent card url does not contain managed agent "bravo" endpoint

  Scenario: A2A surface fetches the agent card from the configured Target path
    Given the surface fetches its agent card from path "/agents/bravo/card.json"
    And managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received the agent card request at path "/agents/bravo/card.json"

  Scenario: A2A surface fetches the agent card from the default well-known path when no override is configured
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received the agent card request at path "/.well-known/agent-card.json"

  Scenario: A2A agent card rewrites every URL-bearing field
    Given managed agent "bravo" publishes an agent card with extra URL fields
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card url points to the gateway listen address
    And the agent card url does not contain managed agent "bravo" endpoint
    And the agent card field "endpoint" points to the gateway listen address
    And the agent card field "endpoint" does not contain managed agent "bravo" endpoint
    And the agent card first endpoint url points to the gateway listen address
    And the agent card first endpoint url does not contain managed agent "bravo" endpoint

  Scenario: A2A agent card omits the trust-registry extension when no trust-registry config is set
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received the agent card request
    And the agent card does not contain the trust-registry extension

  Scenario: A2A agent card carries the agentDid and agentDNA fields when a did:webvh identity is configured
    Given the surface has a did:webvh managed identity with agentDNA "alpha-dna"
    And managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received the agent card request
    And the agent card carries the agentDid field "did:webvh:example.com:bdd-managed-agent"
    And the agent card carries the agentDNA field "alpha-dna"

  Scenario: A2A agent card omits the agentDid and agentDNA fields when no did:webvh identity is configured
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received the agent card request
    And the agent card does not carry the agentDid field
    And the agent card does not carry the agentDNA field
