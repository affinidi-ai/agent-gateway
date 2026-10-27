Feature: MCP authorization server discovery
  An MCP surface whose source authentication takes JWT Bearer tokens can publish
  protected resource metadata (RFC 9728) that names the authorization server
  issuing them, so an MCP client finds where to get a token without manual
  configuration. A caller without a valid token is answered with a challenge
  that points at that metadata. Only tokens issued for the surface itself are
  accepted. A surface that does not publish it behaves as before.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication

  Scenario: An MCP surface publishes its protected resource metadata
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the response includes header "cache-control" with value "no-store"
    And the protected resource metadata names the surface as the resource
    And the protected resource metadata names authorization server "https://idp.example/realms/agents"
    And the protected resource metadata lists scope "tools"

  Scenario: A caller without a token is told where to get one
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    When the caller asks the MCP surface for available tools without a token
    Then the response status is 401
    And the response challenges the caller to fetch a token from the surface's protected resource metadata
    And MCP server "bravo" was not called

  Scenario Outline: A caller with an invalid token is told to get a new one
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 401
    And the response challenges the caller for a new token because the token is invalid
    And MCP server "bravo" was not called

    Examples:
      | auth condition                           |
      | with an expired token                    |
      | with a malformed token                   |
      | with a token from an untrusted issuer    |
      | with a token issued for another resource |

  Scenario: A caller with a valid token reaches the MCP server
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: The caller's token never reaches the MCP server
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 200
    And MCP server "bravo" did not receive header "authorization"

  Scenario: An MCP surface without discovery publishes no metadata
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404
