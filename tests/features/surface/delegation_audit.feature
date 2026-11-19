Feature: Delegation audit log
  The gateway audits what was decided about delegated access, such as a
  consent given, and writes what it does with a delegated credential on each
  call to its log: a prompt for consent, a credential injected. Neither holds
  delegated credential secrets.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the surface has an explicit inbound identity slot for MCP
    And the surface requires delegated credentials from OAuth provider "calendar"
    And the VP Audit Log keeps every audit event
    And the gateway keeps its log of delegation events

  Scenario: Operator sees the consent a caller gave in delegation audit
    Given caller "alice" has been asked to complete OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and a valid inbound identity payload
    When the operator reads the delegation audit trail
    Then the audit read response status is 200
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"
    And the delegation audit trail identifies caller "alice"
    And the delegation audit trail identifies the caller Agent DID
    And the delegation audit trail identifies MCP tool "schedule_meeting"

  Scenario: A prompt for consent and a use of a delegated credential are logged, not audited
    Given caller "alice" has been asked to complete OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token and a valid inbound identity payload
    Then the response status is 200
    And the gateway log records delegation event "consent_required" for OAuth provider "calendar" naming MCP tool "schedule_meeting"
    And the gateway log records delegation event "token_injected" for OAuth provider "calendar" naming MCP tool "schedule_meeting"
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"
    And the delegation audit trail holds no record of event "consent_required"
    And the delegation audit trail holds no record of event "token_injected"

  Scenario: A gateway set to log no per-call delegation events writes none and still audits consent
    Given the gateway is set to log no per-call delegation events
    And caller "alice" has been asked to complete OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token and a valid inbound identity payload
    Then the response status is 200
    And the gateway log records no delegation event
    And the delegation audit trail contains event "consent_granted" for OAuth provider "calendar"

  Scenario: Operator can tell apart the consents of callers that use the same Agent identity in delegation audit
    Given caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And caller "bob" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    And caller "bob" has completed OAuth consent for provider "calendar"
    When the operator reads the delegation audit trail
    Then the audit read response status is 200
    And the delegation audit trail records a consent to OAuth provider "calendar" by two callers of one Agent DID

  Scenario: The gateway log tells apart callers that use the same Agent identity
    Given caller "alice" has invoked MCP tool "schedule_meeting" with a valid token and caller Agent identity "planner"
    When caller "bob" invokes MCP tool "schedule_meeting" with a valid token and inbound identity field "softwareInfo.name" set to "planner"
    Then the response status is 401
    And the gateway log records delegation event "consent_required" for OAuth provider "calendar" by two callers of one Agent DID
