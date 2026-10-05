Feature: MCP caller context
  The gateway exposes authenticated caller context to surface policy for MCP requests.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And the surface requires "JWT Bearer" source authentication

  Scenario: Caller context policy allows an MCP request from an authorized caller
    Given the surface has a request policy that allows callers in group "research"
    When caller "alice" asks the MCP surface for available tools with a valid token containing group "research"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario Outline: Caller context policy blocks an authenticated caller without group "research"
    Given the surface has a request policy that allows callers in group "research"
    When caller "mallory" asks the MCP surface for available tools <auth condition>
    Then the response status is 403
    And MCP server "bravo" was not called

    Examples:
      | auth condition                                  |
      | with a valid token missing group "research"       |
      | with a valid token containing group "operations"  |
