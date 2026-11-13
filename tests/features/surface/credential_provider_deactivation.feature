Feature: Credential provider deactivation
  A deactivated credential provider takes no new consent. The delegated
  credentials people already consented to are used as before, and the
  provider is never deleted by it, so it can be activated again.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from OAuth provider "calendar"

  Scenario: A deactivated provider keeps serving the consent it has
    Given caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And an operator has deactivated OAuth provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"

  Scenario: A deactivated provider asks a caller for no new consent
    Given caller "alice" has no delegated credentials for OAuth provider "calendar"
    And an operator has deactivated OAuth provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 503
    And MCP server "bravo" was not called

  Scenario: A provider activated again asks for consent as before
    Given caller "alice" has no delegated credentials for OAuth provider "calendar"
    And an operator has deactivated OAuth provider "calendar"
    And an operator has activated OAuth provider "calendar" again
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
