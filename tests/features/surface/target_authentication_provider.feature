Feature: Target Authentication through an OAuth provider
  A surface can send its Target the gateway's own access token, obtained from an
  OAuth provider with the Client Credentials grant or for an assertion the gateway
  signs with its own key (the JWT bearer grant), instead of a static secret.
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

  Scenario Outline: A public read other than the agent card carries no gateway token
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp"
    When the caller reads public path "<path>" of the surface
    Then the response status is 200
    And managed agent "bravo" received 1 request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 0 token requests

    Examples:
      | path              |
      | /discovery        |
      | /.well-known/ucp  |

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

  Scenario Outline: The agent card fetch carries a gateway token granted for a signed assertion
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | <algorithm>          |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    When the caller fetches the agent card
    Then the response status is 200
    And every request managed agent "bravo" received carried the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" accepted 1 assertion
    And every assertion OAuth provider "agent-idp" accepted is signed with "<algorithm>"

    Examples:
      | algorithm |
      | RS256     |
      | ES256     |

  Scenario: The signed assertion carries the provider's issuer, subject and token endpoint and a short lifetime
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | RS256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And OAuth provider "agent-idp" accepted 1 assertion
    And every assertion OAuth provider "agent-idp" accepted has issuer "gateway@example.test"
    And every assertion OAuth provider "agent-idp" accepted has subject "alpha@example.test"
    And every assertion OAuth provider "agent-idp" accepted is addressed to its token endpoint
    And every assertion OAuth provider "agent-idp" accepted expires within 300 seconds

  Scenario: One gateway token granted for a signed assertion serves the card fetch and every call
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | ES256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    And the caller has fetched the agent card
    And the caller has sent a request to the surface with a valid API key
    When the caller sends a request to the surface with a valid API key
    Then managed agent "bravo" received 3 requests
    And every request managed agent "bravo" received carried the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 1 token request
    And OAuth provider "agent-idp" accepted 1 assertion

  Scenario: A caller that failed source authentication causes no signed assertion
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | ES256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    When the caller sends a request to the surface with an invalid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 0 token requests

  Scenario: The agent card fetch is refused when the provider no longer trusts the signing key
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | RS256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    And OAuth provider "agent-idp" no longer trusts the gateway signing key
    When the caller fetches the agent card
    Then the response status is 502
    And the response body is error "agent_card_target_auth_failed"
    And the response does not reveal the signing key, the gateway token or the token endpoint of OAuth provider "agent-idp"
    And managed agent "bravo" was not called
    And OAuth provider "agent-idp" received 1 token request
    And OAuth provider "agent-idp" accepted 0 assertions

  Scenario: A call is refused when the provider no longer trusts the signing key
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | ES256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    And OAuth provider "agent-idp" no longer trusts the gateway signing key
    When the caller sends a request to the surface with a valid API key
    Then the response status is 502
    And the response body reports only that Target authentication failed
    And the response does not reveal the signing key, the gateway token or the token endpoint of OAuth provider "agent-idp"
    And managed agent "bravo" was not called
    And OAuth provider "agent-idp" received 1 token request
    And OAuth provider "agent-idp" accepted 0 assertions

  Scenario: A call is forwarded without a token when the provider no longer trusts the signing key and the fallback is passthrough
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | ES256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
      | fallback  | passthrough          |
    And OAuth provider "agent-idp" no longer trusts the gateway signing key
    When the caller sends a request to the surface with a valid API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" did not receive the gateway token from OAuth provider "agent-idp"
    And OAuth provider "agent-idp" received 1 token request
    And OAuth provider "agent-idp" accepted 0 assertions

  Scenario: The operator reading the provider does not see its signing key
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | RS256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    When the operator reads OAuth provider "agent-idp" through the admin API
    Then the admin API response status is 200
    And the admin API response names assertion issuer "gateway@example.test"
    And the admin API response does not reveal the signing key

  Scenario: The operator reading the signing key secret does not see the key
    Given the surface sends its Target a gateway token from OAuth provider "agent-idp" for a signed assertion
      | algorithm | RS256                |
      | issuer    | gateway@example.test |
      | subject   | alpha@example.test   |
    When the operator reads the signing key secret of OAuth provider "agent-idp" through the admin API
    Then the admin API response status is 200
    And the admin API response describes the signing key secret of OAuth provider "agent-idp"
    And the admin API response does not reveal the signing key
