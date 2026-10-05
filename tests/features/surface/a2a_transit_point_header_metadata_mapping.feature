Feature: Header Metadata Mapping on A2A Transit Points
  Header Metadata Mapping copies selected managed-agent request headers into A2A metadata
  at a Transit Point before outbound identity, policy, trust, and forwarding controls evaluate the request.

  Background:
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"

  Scenario: Transit Point strips mapped managed-agent headers when configured to strip them
    Given transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" is configured to strip mapped headers before forwarding
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then the response status is 200
    And external agent "charlie" received A2A metadata field "entra_agent_id" with value "agent-123"
    And external agent "charlie" received A2A metadata field "client_tenant_id" with value "tenant-456"
    And external agent "charlie" did not receive header "x-ms-entra-agent-id"
    And external agent "charlie" did not receive header "x-ms-client-tenant-id"

  Scenario: Transit Point preserves mapped managed-agent headers when configured to preserve them
    Given transit point "tr1" maps managed-agent header "x-ms-client-session-id" to A2A metadata field "session_id"
    And transit point "tr1" is configured to preserve mapped headers before forwarding
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-client-session-id" set to "session-123"
    Then the response status is 200
    And external agent "charlie" received A2A metadata field "session_id" with value "session-123"
    And external agent "charlie" received header "x-ms-client-session-id" with value "session-123"

  Scenario: TP-specific managed identity is derived from mapped Copilot Studio headers
    Given transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then the response status is 200
    And external agent "charlie" received the forwarded request with a VP containing outbound managed-agent identity field "entra_agent_id" with value "agent-123"
    And external agent "charlie" received the forwarded request with a VP containing outbound managed-agent identity field "client_tenant_id" with value "tenant-456"

  Scenario: Missing required mapped identity headers reject before Transit Point forwarding
    Given transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" without header "x-ms-client-tenant-id"
    Then the response is a protected identity validation error
    And external agent "charlie" was not called

  Scenario: Unsupported Transit Point protocols reject Header Metadata Mapping configuration
    Given the operator can use the admin API and no surface is configured for route "/example-unsupported-transit"
    When the operator attempts to create an MCP Transit Point mapping managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    Then the admin API response status is 400
    And the admin API error response mentions "header metadata mapping"
