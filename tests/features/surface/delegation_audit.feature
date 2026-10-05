Feature: Delegation audit log
  The gateway records credential delegation decisions without storing delegated
  credential secrets in the audit trail.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the surface has an explicit inbound identity slot for MCP
    And the surface requires delegated credentials from OAuth provider "calendar"

  Scenario: Operator sees a complete consent-to-use sequence in delegation audit
    Given caller "alice" has been asked to complete OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and a valid inbound identity payload
    When the operator reads the delegation audit trail
    Then the audit read response status is 200
    And the delegation audit trail contains event "consent_required" for OAuth provider "calendar"
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"
    And the delegation audit trail contains event "token_injected" for OAuth provider "calendar"
    And the delegation audit trail identifies caller "alice"
    And the delegation audit trail identifies the caller Agent DID
    And the delegation audit trail identifies MCP tool "schedule_meeting"

  Scenario: Operator can distinguish authenticated callers using the same Agent identity in delegation audit
    Given caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    And caller "bob" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    When the operator reads the delegation audit trail
    Then the audit read response status is 200
    And the delegation audit trail contains distinct authenticated caller records for "alice" and "bob"
    And both audit records are bound to caller Agent identity "planner"
    And both audit records identify the same caller Agent DID
