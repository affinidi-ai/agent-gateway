Feature: Consent confirmation through a Transit Point
  Consent confirmation does not cover consent asked for through a Transit Point: a caller's
  consent start there goes straight to the OAuth provider, with no sign-in at the callers'
  identity provider.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And Transit Point "alpha" authenticates its callers with JWT Bearer
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" injects delegated credentials from OAuth provider "calendar"

  Scenario: A JWT caller's consent start through a Transit Point goes straight to the OAuth provider
    Given OAuth provider "calendar" confirms its caller at the identity provider
    And managed agent "example-agent" has started OAuth consent for provider "calendar" through Transit Point "alpha" for JWT caller "alice"
    When caller "alice" confirms the consent start page for provider "calendar"
    Then the consent start response status is 302
    And the consent start response sends the browser to OAuth provider "calendar"
