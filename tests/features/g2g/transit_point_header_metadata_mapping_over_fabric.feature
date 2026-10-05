Feature: Transit Point Header Metadata Mapping over Fabric
  A managed agent can present identity-bearing headers only when it calls a Transit Point.
  Gateway 1 normalizes those headers into A2A metadata, derives the outbound managed-agent identity,
  and carries the existing identity proof to Gateway 2 over Fabric.

  Scenario: Gateway 2 receives managed-agent identity derived from Transit Point mapped headers
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And transit point "tr1" maps managed-agent header "x-ms-entra-agent-id" to A2A metadata field "entra_agent_id"
    And transit point "tr1" maps managed-agent header "x-ms-client-tenant-id" to A2A metadata field "client_tenant_id"
    And transit point "tr1" derives outbound managed-agent identity from mapped A2A metadata fields "entra_agent_id" and "client_tenant_id"
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1" with header "x-ms-entra-agent-id" set to "agent-123" and header "x-ms-client-tenant-id" set to "tenant-456"
    Then managed agent "bravo" received the forwarded request with a VP containing outbound managed-agent identity field "entra_agent_id" with value "agent-123"
    And managed agent "bravo" received the forwarded request with a VP containing outbound managed-agent identity field "client_tenant_id" with value "tenant-456"
    And the response status is 200
    And the A2A response result matches managed agent "bravo" response result
