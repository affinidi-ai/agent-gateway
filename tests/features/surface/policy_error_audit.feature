Feature: Policy errors are audited
  A policy that cannot reach a decision denies the request, and the denial is
  recorded in the VP Audit Log as an error decision.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And the surface requires "JWT Bearer" source authentication
    And the VP Audit Log keeps every audit event

  Scenario: A request policy that fails to evaluate denies and is recorded as an error
    Given the surface has a request policy that fails to evaluate
    When caller "alice" asks the MCP surface for available tools with a valid token containing group "research"
    Then the response status is 403
    And MCP server "bravo" was not called
    And the VP Audit Log records that the request policy failed to evaluate
