Feature: Discovery reads through a Transit Point
  A GET or HEAD of a discovery document through a Transit Point needs a transit token like any
  other Transit Point request, passes the Transit Point's policy, and reaches the destination
  without a caller credential.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "metadata" routes to MCP server "meta-target"

  Scenario Outline: A <method> discovery read with a valid transit token is forwarded
    Given Transit Point "metadata" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with <method> through Transit Point "metadata" with its transit token
    Then the response status is 200
    Examples:
      | method |
      | GET    |
      | HEAD   |

  Scenario Outline: A <method> discovery read without a transit token is refused
    Given Transit Point "metadata" requires a transit token
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with <method> through Transit Point "metadata"
    Then the response status is 401
    And MCP server "meta-target" was not called
    Examples:
      | method |
      | GET    |
      | HEAD   |

  Scenario: A discovery read with a transit token issued for another surface is refused
    Given Transit Point "metadata" requires a transit token
    And managed agent "example-agent" holds a transit token the gateway issued for surface "another-surface"
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with GET through Transit Point "metadata" with its transit token
    Then the response status is 401
    And MCP server "meta-target" was not called

  Scenario: A discovery read with a transit token whose signature was altered is refused
    Given Transit Point "metadata" requires a transit token
    And managed agent "example-agent" holds a transit token whose signature was altered
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with GET through Transit Point "metadata" with its transit token
    Then the response status is 401
    And MCP server "meta-target" was not called

  Scenario: A discovery read without a transit token is forwarded when the Transit Point does not require one
    Given Transit Point "metadata" does not require a transit token
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with GET through Transit Point "metadata"
    Then the response status is 200

  Scenario: A Transit Point policy can refuse a discovery read
    Given Transit Point "metadata" requires a transit token
    And Transit Point "metadata" has a policy that allows only caller "alice"
    And managed agent "example-agent" holds a transit token naming caller "bob"
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with GET through Transit Point "metadata" with its transit token
    Then the response status is 403
    And MCP server "meta-target" was not called

  Scenario: A discovery read reaches the destination without the delegated credential
    Given Transit Point "metadata" requires a transit token
    And Transit Point "metadata" injects delegated credentials from API-key provider "weather"
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" reads "/.well-known/agent-card.json" with GET through Transit Point "metadata" with its transit token
    Then the response status is 200
    And MCP server "meta-target" received the discovery read without header "Authorization"
