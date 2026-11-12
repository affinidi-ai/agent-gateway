Feature: Credentials an A2A Transit Point sends to its external agent
  An A2A Transit Point can authenticate to its external agent with a token from a
  credential provider, or send the delegated credential of the caller it authenticated.
  The gateway supplies the credential, never the managed agent, and a Transit Point that
  cannot supply it does not forward the request.

  Background:
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"

  Scenario: An A2A Transit Point sends its external agent a provider token in place of the managed agent's credential
    Given the gateway authenticates to the destination of Transit Point "tr1" with a client credentials provider
    And Transit Point "tr1" authenticates its callers with API key "caller-key-1"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-api-key" set to "caller-key-1" and header "Authorization" set to "Bearer chosen-by-the-agent"
    Then the response status is 200
    And external agent "charlie" received header "authorization" with value "Bearer bdd-target-provider-token"
    And external agent "charlie" did not receive header "x-api-key"
    And the credential provider received 1 token request

  Scenario: An A2A Transit Point whose credential provider refuses a token does not forward the request
    Given the gateway authenticates to the destination of Transit Point "tr1" with a client credentials provider
    And the credential provider is refusing token requests
    And Transit Point "tr1" authenticates its callers with API key "caller-key-1"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-api-key" set to "caller-key-1"
    Then the response status is 502
    And the response mentions "Target authentication credentials unavailable"
    And external agent "charlie" was not called

  Scenario: An A2A Transit Point without the managed agent's identity refuses to send a delegated credential
    Given Transit Point "tr1" injects delegated credentials from OAuth provider "calendar"
    And Transit Point "tr1" authenticates its callers with API key "caller-key-1"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-api-key" set to "caller-key-1"
    Then the response status is 403
    And the response mentions "Delegated credentials need the managed agent's identity"
    And external agent "charlie" was not called

  Scenario: An A2A Transit Point asks a caller without a grant for consent before its external agent is reached
    Given Transit Point "tr1" injects delegated credentials from OAuth provider "calendar"
    And Transit Point "tr1" authenticates its callers with API key "caller-key-1"
    And Transit Point "tr1" has a managed identity of its own
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tr1" with header "x-api-key" set to "caller-key-1"
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And external agent "charlie" was not called
