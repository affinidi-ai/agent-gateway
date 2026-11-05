Feature: Rate limiting is audited
  A request the Access Point refuses because the surface's rate limit is
  reached, or a Transit Point refuses because its caller reached the
  Transit Point's per-caller limit, is recorded in the VP Audit Log.

  Scenario: A request over the surface rate limit is refused and recorded
    Given an A2A surface targeting managed agent "bravo"
    And the surface admits 1 request per minute
    And the VP Audit Log keeps every audit event
    And the surface rate limit is reached
    When the caller sends a request to the surface
    Then the response status is 429
    And the response carries a non-empty "retry-after" header
    And managed agent "bravo" received exactly 1 request
    And the VP Audit Log records the surface rate limit refusal

  Scenario: A caller over a Transit Point's per-caller limit is refused and recorded
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" admits 1 request per minute from each caller
    And the VP Audit Log keeps every audit event
    And managed agent "example-agent" holds a transit token naming caller "alice"
    And caller "alice" has reached the per-caller limit of Transit Point "alpha"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 429
    And the response carries a non-empty "retry-after" header
    And MCP server "bravo" received exactly 1 request
    And the VP Audit Log records the per-caller rate limit refusal of caller "alice" on Transit Point "alpha"
