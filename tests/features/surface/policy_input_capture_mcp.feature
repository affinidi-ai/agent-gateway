Feature: Live policy input capture on an MCP surface
  An operator listening to an MCP surface's policy input sees the input and
  decision of the surface's request policy for each MCP request, including the
  MCP method the caller sent.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And surface "alpha" has a request policy that allows every request

  Scenario: The Capture view shows the MCP method of a request its policy decided
    Given the operator listens to the policy input of surface "alpha"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "tools/list"
