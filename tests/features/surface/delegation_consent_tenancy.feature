Feature: Tenant reads of the consent an OAuth callback records
  The OAuth callback records a consent_granted that names its credential
  provider's id, as every other delegation audit record does, so the tenant
  that owns the provider reads it. A provider's slug is unique only per
  tenant, so another tenant that has a provider with the same slug reads
  none of it.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the surface has an explicit inbound identity slot for MCP
    And the surface requires delegated credentials from OAuth provider "calendar"
    And the VP Audit Log keeps every audit event
    And the surface belongs to tenant "tenant-a"
    And OAuth provider "calendar" belongs to tenant "tenant-a"
    And tenant "tenant-b" owns the credential provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    And caller "alice" has been asked to complete OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the Credential Delegation Audit Log holds the consent granted for OAuth provider "calendar"

  Scenario: A tenant token reads the consent its own tenant's OAuth provider recorded
    When a token of tenant "tenant-a" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the audit read shows the consent granted for OAuth provider "calendar" of tenant "tenant-a"

  Scenario: Another tenant with a provider of the same slug reads none of the consent
    When a token of tenant "tenant-b" reads the Credential Delegation Audit Log
    Then the audit read response status is 200
    And the audit read shows no record
