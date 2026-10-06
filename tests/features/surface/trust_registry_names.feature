Feature: Managed agent display names
  The gateway names a managed agent after the name in its target's Agent Card on
  A2A and AP2 surfaces, and after its surface otherwise or when the card has no
  valid name. The display name appears in the Agent Identity credential the gateway
  issues for the managed agent and in the trust registry entity reference field for
  the managed agent's DID. Callers are never named after the surface, and naming
  never blocks forwarding.

  Scenario: The managed agent's credential carries the surface name when its Agent Card has no name
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then the response status is 200
    And external agent "charlie" received the forwarded request with a VP naming the managed agent "alpha"

  Scenario: The managed agent's credential carries its Agent Card name
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    And managed agent "bravo" serves an Agent Card named "DateTime Agent"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then the response status is 200
    And external agent "charlie" received the forwarded request with a VP naming the managed agent "DateTime Agent"

  Scenario: A caller's credential carries no display name
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And surface "alpha" requires "API Key" source authentication
    And surface "alpha" maps inbound header "x-agent-id" to A2A metadata field "agent_id"
    And surface "alpha" maps inbound header "x-tenant-id" to A2A metadata field "tenant_id"
    And surface "alpha" derives inbound identity from mapped A2A metadata fields "agent_id" and "tenant_id"
    When the caller sends an A2A message/send request to surface "alpha" with a valid API key and mapped identity headers for agent "agent-789" and tenant "tenant-456"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with a VP that names no agent

  @wip
  Scenario: Trust Recorder publishes the managed agent's display name
    Given an A2A surface targeting managed agent "bravo"
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    When the caller sends a request to the surface
    Then the response status is 200
    And trust registry "alpha-registry" received an entity reference field naming the managed agent after the surface
    And trust registry "alpha-registry" received a recognition record for the managed agent with the surface display name as context

  @wip
  Scenario: Trust Recorder still records the managed agent when the display name is rejected
    Given an A2A surface targeting managed agent "bravo"
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And trust registry "alpha-registry" is rejecting reference fields
    When the caller sends a request to the surface
    Then the response status is 200
    And trust registry "alpha-registry" received a recognition record for the managed agent as an owned agent of issuer "did:web:example.com:issuer"

  @wip
  Scenario: Renaming a surface republishes the managed agent's display name
    Given an A2A surface targeting managed agent "bravo"
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And trust registry "alpha-registry" has an entity reference field naming the managed agent after the surface
    When the operator renames the surface to "delta"
    Then the admin API response status is 200
    And trust registry "alpha-registry" received an entity reference field update naming the managed agent "delta"
