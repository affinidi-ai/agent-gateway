Feature: Header Metadata Mapping on A2A Access Points
  Header Metadata Mapping copies selected inbound HTTP headers into A2A metadata
  before identity, policy, trust, and forwarding controls evaluate the request.
  The copied metadata is protocol context; sensitive transport headers are not
  copied into metadata or leaked to the Target.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target

  Scenario: Selected caller headers become A2A metadata before forwarding
    Given surface "alpha" maps inbound header "x-agent-id" to A2A metadata field "agent_id"
    And surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    When the caller sends an A2A message/send request to surface "alpha" with mapped identity headers
    Then the response status is 200
    And managed agent "bravo" received A2A metadata field "agent_id" with value "agent-123"
    And managed agent "bravo" received A2A metadata field "tenant_id" with value "tenant-456"
    And managed agent "bravo" did not receive header "x-agent-id"
    And managed agent "bravo" did not receive header "x-tenant-id"

  Scenario: Mapped header values are visible to surface policy
    Given surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" has request policy "tenant policy" that allows A2A metadata field "tenant_id" only when it equals "tenant-456"
    When the caller sends an A2A message/send request to surface "alpha" with header "x-tenant-id" set to "tenant-456"
    Then the response status is 200
    And managed agent "bravo" received a forwarded request

  Scenario: Surface policy rejects callers using mapped header metadata
    Given surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" has request policy "tenant policy" that allows A2A metadata field "tenant_id" only when it equals "tenant-456"
    When the caller sends an A2A message/send request to surface "alpha" with header "x-tenant-id" set to "tenant-denied"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: Header-derived identity produces caller Agent DIDs from mapped identity fields
    Given surface "alpha" requires "API Key" source authentication
    And surface "alpha" maps inbound header "x-agent-id" to A2A metadata field "agent_id"
    And surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" derives inbound identity from mapped A2A metadata fields "agent_id" and "tenant_id"
    And the caller has sent an A2A message/send request to surface "alpha" with a valid API key and mapped identity headers
    When the caller sends an A2A message/send request to surface "alpha" with a valid API key and mapped identity headers for agent "agent-789" and tenant "tenant-456"
    Then the response status is 200
    And managed agent "bravo" received two forwarded requests with VPs proving different caller Agent DIDs

  Scenario: Non-identity mapped headers do not affect caller Agent DID derivation
    Given surface "alpha" requires "API Key" source authentication
    And surface "alpha" maps inbound header "x-agent-id" to A2A metadata field "agent_id"
    And surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" maps inbound header "x-correlation-id" to A2A metadata field "correlation_id"
    And surface "alpha" derives inbound identity from mapped A2A metadata fields "agent_id" and "tenant_id"
    And the caller has sent an A2A message/send request to surface "alpha" with correlation header "correlation-a"
    When the caller sends an A2A message/send request to surface "alpha" with correlation header "correlation-b"
    Then the response status is 200
    And managed agent "bravo" received two forwarded requests with VPs proving the same caller Agent DID

  Scenario: Trust Check templates can decide from mapped header metadata
    Given surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" has caller Trust Check that uses A2A metadata field "tenant_id"
    When the caller sends an A2A message/send request to surface "alpha" without header "x-tenant-id"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: Missing optional mapped headers do not block forwarding
    Given surface "alpha" maps inbound header "x-agent-session-id" to A2A metadata field "session_id"
    When the caller sends an A2A message/send request to surface "alpha" without header "x-agent-session-id"
    Then the response status is 200
    And managed agent "bravo" received a forwarded request
    And managed agent "bravo" did not receive A2A metadata field "session_id"

  Scenario Outline: Sensitive headers cannot be mapped into A2A metadata
    Given the operator can use the admin API and no surface is configured for route "/example-sensitive"
    When the operator attempts to create an A2A surface for route "/example-sensitive" mapping inbound header <header> to A2A metadata field "blocked"
    Then the admin API response status is 400
    And the admin API error response mentions "sensitive header"

    Examples:
      | header               |
      | "authorization"      |
      | "cookie"             |
      | "x-agent-token"      |

  Scenario: Source-auth credentials are stripped even when mapped headers are preserved
    Given surface "alpha" requires "API Key" source authentication
    And surface "alpha" maps inbound header "x-agent-session-id" to A2A metadata field "session_id"
    And surface "alpha" preserves mapped headers when forwarding
    When the caller sends an A2A message/send request to surface "alpha" with a valid API key and header "x-agent-session-id" set to "session-123"
    Then the response status is 200
    And managed agent "bravo" received header "x-agent-session-id" with value "session-123"
    And managed agent "bravo" did not receive header "x-api-key"
