Feature: Credential policy on custom metadata
  A tenant surface's custom metadata may name a secret with "$SECRET:<id>". The gateway
  resolves a secret of the surface's own tenant. An appliance-wide secret is sent while
  tenant credential isolation only warns, and refused once the gateway enforces it. Another
  tenant's secret is never sent.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    And the surface belongs to tenant "tenant-a"
    And the gateway keeps its log of warnings

  Scenario: A tenant surface sends an appliance-wide secret in custom metadata in warn mode
    Given the surface injects custom metadata key "credential" value "$SECRET:appliance-key" into "meta"
    And the appliance holds the secret "appliance-key"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received MCP _meta key "credential" with value "bdd-secret-value"
    And the gateway log has a warning containing "Custom metadata secret is appliance-wide on a tenant surface; refused once tenant_credential_isolation is enforce"

  Scenario: A tenant surface cannot send an appliance-wide secret in custom metadata when tenant isolation is enforced
    Given the surface injects custom metadata key "credential" value "$SECRET:appliance-key" into "meta"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    And the appliance holds the secret "appliance-key"
    When the caller asks the MCP surface for available tools
    Then the response status is 500
    And MCP server "bravo" was not called
    And the gateway log has a warning containing "Refusing custom metadata secret outside the surface's tenant"

  Scenario: A tenant surface never sends another tenant's secret in custom metadata
    Given the surface injects custom metadata key "credential" value "$SECRET:other-key" into "meta"
    And tenant "tenant-b" holds the secret "other-key"
    When the caller asks the MCP surface for available tools
    Then the response status is 500
    And MCP server "bravo" was not called
    And the gateway log has a warning containing "Refusing custom metadata secret outside the surface's tenant"
