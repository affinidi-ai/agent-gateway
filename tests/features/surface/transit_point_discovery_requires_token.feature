Feature: Transit Point Discovery Requires Token Authentication
  Discovery requests on Transit Points now require a valid transit token and must pass
  through trust checks and OPA policy evaluation. This closes the security gap where
  unauthenticated requests could reach a target service via discovery paths.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "metadata" routes to MCP server "meta-target"

  # ===================================================================
  # Core Scenarios: Discovery with Valid Token (GET and HEAD Methods)
  # ===================================================================

  Scenario: GET discovery document with valid transit token is forwarded
    Given Transit Point "metadata" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it
    When managed agent "example-agent" sends GET "/.well-known/agent-card.json" with transit token through Transit Point "metadata"
    Then the response status is 200 from discovery request

  Scenario: HEAD discovery document with valid transit token is forwarded
    Given Transit Point "metadata" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it
    When managed agent "example-agent" sends HEAD "/.well-known/agent-card.json" with transit token through Transit Point "metadata"
    Then the response status is 200 from discovery request

  Scenario: GET discovery document without transit token is rejected with 401
    Given Transit Point "metadata" requires a transit token
    When managed agent "example-agent" sends GET "/.well-known/agent-card.json" without transit token through Transit Point "metadata"
    Then the response status is 401 from discovery request
