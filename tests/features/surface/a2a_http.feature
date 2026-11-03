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

  Scenario: A2A agent card without the identity extension is served without an identity credential
    Given the surface has managed identity enabled
    And managed agent "bravo" publishes an agent card without the agent-identity extension
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card url points to the gateway listen address
    And the agent card does not contain the credential extension

  Scenario: A2A agent card whose identity credential names a different DID than its presentation is refused
    Given the surface has managed identity enabled
    And managed agent "bravo" publishes an agent card whose identity credential names a different DID than its presentation
    When the caller fetches the agent card
    Then the response is a "protected_identity" identity validation error

  Scenario: A2A response from the managed agent without the agent-identity extension is refused
    Given the surface has managed identity enabled
    And managed agent "bravo" responds without the agent-identity extension
    When the caller sends a request to the surface
    Then the response is a "protected_identity" identity extension missing error
    And managed agent "bravo" received the forwarded request

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
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: A caller cannot override or ride along on the credentialed agent card fetch
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
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
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And managed agent "bravo" redirects its agent card to managed agent "charlie"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_upstream_redirected"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And managed agent "charlie" was not called

  Scenario: A missing target credential fails the agent card when fallback is reject
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "reject"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And managed agent "bravo" was not called

  Scenario: A missing target credential fetches the agent card without it when fallback is passthrough
    Given the gateway authenticates to the managed agent with missing secret "bdd-missing-target-secret" in header "x-target-api-key", falling back to "passthrough"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: A2A agent card fetch presents a provider-issued target credential
    Given the gateway authenticates to the managed agent with a client credentials provider
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request
    And the credential provider received a client credentials grant from client "bdd-target-client" for scope "https://www.googleapis.com/auth/cloud-platform"

  Scenario: A second agent card fetch reuses the cached provider token
    Given the gateway authenticates to the managed agent with a client credentials provider
    And the caller has fetched the agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  # A token is renewed 60 seconds before it expires, so a 60 second token is already stale.
  Scenario: A provider token about to expire is renewed before the agent card fetch
    Given the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider issues tokens that expire in 60 seconds
    And the caller has fetched the agent card
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 2 token requests

  Scenario: A refused provider token request fails the agent card when fallback is reject
    Given the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider is refusing token requests
    And the gateway's authentication to the managed agent falls back to "reject"
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And managed agent "bravo" was not called

  Scenario: A refused provider token request fetches the agent card without it when fallback is passthrough
    Given the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider is refusing token requests
    And the gateway's authentication to the managed agent falls back to "passthrough"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" did not receive header "authorization"

  Scenario: A2A agent card fetch presents a token from a JWT Bearer grant
    Given the gateway authenticates to the managed agent with a JWT Bearer provider
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received a JWT Bearer grant signed with the provider key
    And the credential provider's latest token request has no client ID or secret in its form body

  Scenario: A forwarded request presents a provider-issued target credential
    Given the gateway authenticates to the managed agent with a client credentials provider
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"
    And the credential provider received 1 token request

  Scenario: A caller cannot override the provider-issued credential on the agent card fetch
    Given the gateway authenticates to the managed agent with a client credentials provider
    When the caller fetches the agent card with extra headers
      | authorization | Bearer caller-forged |
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Bearer bdd-target-provider-token"

  Scenario: Without a target credential the agent card fetch forwards caller headers except cookies
    When the caller fetches the agent card with extra headers
      | x-request-id | req-caller     |
      | cookie       | session=caller |
    Then the response status is 200
    And managed agent "bravo" received header "x-request-id" with value "req-caller"
    And managed agent "bravo" did not receive header "cookie"
    And managed agent "bravo" did not receive header "x-target-api-key"

  Scenario: The target credential is sent on a GET of the well-known agent card
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request to the surface route path "/.well-known/agent-card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent on a GET of the legacy well-known agent card
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request to the surface route path "/.well-known/agent.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent on a GET of the well-known agent card with a query string
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request to the surface route path "/.well-known/agent-card.json?probe=1"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent on a HEAD of the well-known agent card
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a HEAD request to the surface route path "/.well-known/agent-card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent on a HEAD of the legacy well-known agent card
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a HEAD request to the surface route path "/.well-known/agent.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent on a HEAD of the well-known agent card with a query string
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a HEAD request to the surface route path "/.well-known/agent-card.json?probe=1"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario: The target credential is sent to the configured agent card location
    Given the surface fetches its agent card from path "/agents/bravo/card.json"
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request to the surface route path "/.well-known/agent-card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/agents/bravo/card.json"
    And managed agent "bravo" received header "x-target-api-key" with value "bdd-target-secret"

  Scenario Outline: The target credential is not sent on a public discovery read that is not the agent card
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request to the surface route path "<path>"
    Then managed agent "bravo" received a GET request at path "<forwarded path>"
    And managed agent "bravo" did not receive header "x-target-api-key"

    Examples:
      | path                | forwarded path      |
      | /discovery          | /discovery          |
      | /.well-known/ucp    | /.well-known/ucp    |
      | /x/%2e%2e/discovery | /discovery          |

  Scenario: A POST to a path that only ends like an agent card runs the surface policy
    Given the surface has a request policy that denies all requests
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a POST request to the surface route path "/rpc/agent-card.json"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A POST to the well-known agent card path is answered by the gateway's own card GET before policy
    Given the surface has a request policy that denies all requests
    When the caller sends a POST request to the surface route path "/.well-known/agent-card.json"
    Then managed agent "bravo" received a GET request at path "/.well-known/agent-card.json"
    And managed agent "bravo" did not receive a POST request at path "/.well-known/agent-card.json"

  Scenario: A path whose case differs is not served as the agent card fetch
    Given the surface requires "API Key" source authentication and forwards failed callers to policy
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller sends a GET request without an API key to the surface route path "/.well-known/Agent-Card.json"
    Then the response status is 200
    And managed agent "bravo" received a GET request at path "/.well-known/Agent-Card.json"
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
