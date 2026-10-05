Feature: Custom metadata injection into MCP requests

  The gateway injects operator-configured metadata into MCP requests forwarded
  to the MCP server. The injection target controls whether metadata appears in
  the JSON-RPC _meta field, as HTTP request headers, or both.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog

  Scenario: Custom metadata with meta target injects into the JSON-RPC _meta field only
    Given the surface injects custom metadata key "tenant" value "acme" into "meta"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP _meta key "tenant" with value "acme"
    And MCP server "bravo" did not receive header "x-gateway-tenant"

  Scenario: Custom metadata with headers target injects as HTTP request headers only
    Given the surface injects custom metadata key "tenant" value "acme" into "headers"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received header "x-gateway-tenant" with value "acme"
    And MCP server "bravo" did not receive MCP _meta key "tenant"

  Scenario: Custom metadata with both target injects into _meta field and as HTTP request headers
    Given the surface injects custom metadata key "tenant" value "acme" into "both"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP _meta key "tenant" with value "acme"
    And MCP server "bravo" received header "x-gateway-tenant" with value "acme"
