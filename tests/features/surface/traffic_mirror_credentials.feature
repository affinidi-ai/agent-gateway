Feature: Traffic mirroring never carries a credential
  A surface that mirrors its traffic sends the mirror a copy of each request. The Target
  credential and any delegated credential go only to the Target: the mirrored copy carries
  neither, in a header or in MCP metadata, and a caller header named like the Target
  credential header is not mirrored either.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface mirrors every request to MCP server "charlie"

  Scenario: A delegated credential in MCP metadata reaches the Target but not the mirror
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from OAuth provider "calendar"
    And the surface injects delegated credentials from OAuth provider "calendar" into MCP metadata key "calendar"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received MCP _meta key "calendar" with delegated credential from OAuth provider "calendar"
    And MCP server "charlie" did not receive MCP _meta key "calendar"

  Scenario: A delegated credential header reaches the Target but not the mirror
    Given the surface requires "JWT Bearer" source authentication
    And the surface requires delegated credentials from OAuth provider "calendar"
    And the surface injects delegated credentials from OAuth provider "calendar" as header "x-calendar-token"
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received header "x-calendar-token" with delegated credential from OAuth provider "calendar"
    And MCP server "charlie" did not receive header "x-calendar-token"

  Scenario: The Target credential reaches the Target but not the mirror
    Given the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the caller asks the MCP surface for available tools with header "X-Target-Api-Key" set to "caller-chosen-value"
    Then the response status is 200
    And MCP server "bravo" received header "x-target-api-key" with value "bdd-target-secret"
    And MCP server "charlie" did not receive header "x-target-api-key"
