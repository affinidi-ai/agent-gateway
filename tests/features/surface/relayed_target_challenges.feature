Feature: Target challenges relayed to the caller
  A Target can refuse a request with a WWW-Authenticate challenge. On an MCP
  surface that publishes protected resource metadata, the caller authenticates
  to the gateway, so a Target challenge is addressed to the gateway rather than
  the caller: only the Target's Payment challenges reach the caller, and a
  Target 401 left with no challenge becomes a 502. A surface that does not
  publish the metadata relays every Target challenge unchanged. A Fabric
  route's peer refusals are covered by the gateway's unit tests.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication

  Scenario: A Target refusal left without a challenge becomes a gateway error
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" is refusing requests with status 401 and challenges "Bearer"
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 502
    And the response does not include header "www-authenticate"
    And MCP server "bravo" received the forwarded MCP request

  Scenario Outline: Only the Target's Payment challenge reaches the caller
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" is refusing requests with status <status> and challenges "Bearer Payment"
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is <status>
    And the response relays only the "Payment" challenges of MCP server "bravo"
    And MCP server "bravo" received the forwarded MCP request

    Examples:
      | status |
      | 401    |
      | 402    |

  Scenario: A surface without protected resource metadata relays every Target challenge
    Given MCP server "bravo" is refusing requests with status 401 and challenges "Bearer Payment"
    When the caller asks the MCP surface for available tools with a valid token
    Then the response status is 401
    And the response relays only the "Bearer Payment" challenges of MCP server "bravo"
    And MCP server "bravo" received the forwarded MCP request
