Feature: Target Authentication through an OAuth provider
  A surface can send its Target the gateway's own access token, obtained from an
  OAuth provider with the Client Credentials grant, instead of a static secret.
  The gateway sends it on the agent card fetch and on the calls of callers it
  authenticated, reuses one token across them, and never sends it on behalf of
  an anonymous caller. When the provider cannot grant a token, the surface's
  fallback decides between refusing the request and forwarding it without a
  credential.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication

  Scenario: The agent card fetch carries the gateway token
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp"
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received 1 request
    And every request managed agent "bravo" received carried the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 1 token request

  Scenario: A call from an authenticated caller carries the gateway token
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp"
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received 1 request
    And every request managed agent "bravo" received carried the gateway token from OAuth provider "agent-idp"

  Scenario: One gateway token serves the card fetch and every call
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp"
    And the caller has fetched the agent card
    And the caller has sent a request to the surface with a valid API key
    When the caller sends a request to the surface with a valid API key
    Then managed agent "bravo" received 3 requests
    And every request managed agent "bravo" received carried the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 1 token request

  Scenario: A caller that failed source authentication gets no gateway token
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp"
    When the caller sends a request to the surface with an invalid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 0 token requests

  Scenario: The agent card fetch is refused when the provider is unavailable and the fallback is reject
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" with fallback "reject"
    And OAuth provider "agent-idp" is unavailable
    When the caller fetches the agent card
    Then the response status is 502
    And managed agent "bravo" was not called

  Scenario: A call is refused when the provider is unavailable and the fallback is reject
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" with fallback "reject"
    And OAuth provider "agent-idp" is unavailable
    When the caller sends a request to the surface with a valid API key
    Then the response status is 502
    And managed agent "bravo" was not called

  Scenario: The agent card fetch is forwarded without a token when the provider is unavailable and the fallback is passthrough
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" with fallback "passthrough"
    And OAuth provider "agent-idp" is unavailable
    When the caller fetches the agent card
    Then the response status is 200
    And managed agent "bravo" received 1 request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"

  Scenario: A call is forwarded without a token when the provider is unavailable and the fallback is passthrough
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" with fallback "passthrough"
    And OAuth provider "agent-idp" is unavailable
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"

  Scenario: A failed grant is not retried straight away
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" with fallback "passthrough"
    And OAuth provider "agent-idp" is unavailable
    And the caller has sent a request to the surface with a valid API key
    When the caller sends a request to the surface with a valid API key
    Then managed agent "bravo" received 2 requests
    And OAuth provider "agent-idp" received 1 token request
