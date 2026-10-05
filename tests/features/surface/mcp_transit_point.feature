Feature: MCP Transit Point forwarding
  A Transit Point lets the managed agent make outbound MCP calls through the gateway.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog

  Scenario: MCP tool discovery reaches the external MCP server through a Transit Point
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP tool discovery follows an updated Transit Point explicit path
    Given the operator updates Transit Point "alpha" listen_path to "/transit/alpha-renamed"
    When managed agent "example-agent" asks for available tools through Transit Point path "/transit/alpha-renamed"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP tool discovery stops using the previous Transit Point path after it is renamed
    Given the operator updates Transit Point "alpha" listen_path to "/transit/alpha-renamed"
    When managed agent "example-agent" asks for available tools through Transit Point path "/transit/alpha"
    Then the response status is 404
    And MCP server "bravo" was not called

  Scenario: MCP tool invocation reaches the external MCP server through a Transit Point
    Given MCP server "bravo" supports tool invocation
    When managed agent "example-agent" invokes MCP tool "search" through Transit Point "alpha" with a result limit of 3
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged
    And MCP server "bravo" received forwarded MCP field "params.arguments.limit" unchanged
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result
