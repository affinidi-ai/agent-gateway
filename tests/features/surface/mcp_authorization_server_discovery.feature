Feature: MCP authorization server discovery
  An MCP surface whose source authentication takes JWT Bearer tokens can publish
  protected resource metadata (RFC 9728) that names the authorization server
  issuing them, so an MCP client finds where to get a token without manual
  configuration. A surface that does not publish it behaves as before.

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

  Scenario: An MCP surface without discovery publishes no metadata
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404
