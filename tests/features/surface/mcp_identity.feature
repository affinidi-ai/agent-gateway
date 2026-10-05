Feature: MCP identity handling
  The gateway validates and binds MCP identity metadata through MCP surfaces.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"

  Scenario: MCP tool response raw serverIdentity payload is stripped and replaced with a credential extension when strip_raw_meta is enabled
    Given the surface has managed identity with strip raw metadata enabled
    And MCP server "bravo" includes an agent-identity extension in responses
    When the caller invokes MCP tool "get_news"
    Then MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/call"
    And the response status is 200
    And the MCP surface proxied the MCP response to the caller
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response contains the credential extension
    And the MCP response does not contain the raw serverIdentity payload

  Scenario: MCP tool response raw serverIdentity payload is retained alongside the credential extension by default
    Given the surface has managed identity enabled
    And MCP server "bravo" includes an agent-identity extension in responses
    When the caller invokes MCP tool "get_news"
    Then MCP server "bravo" received the forwarded MCP request
    And the response status is 200
    And the MCP response contains the credential extension
    And the MCP response contains the raw serverIdentity payload

  Scenario: Schema-invalid MCP serverIdentity response is rejected by the protected identity slot
    Given the surface has managed identity enabled
    And MCP server "bravo" returns a schema-invalid serverIdentity payload
    When the caller invokes MCP tool "get_news"
    Then the response status is 422
    And the response is a "protected_identity" identity validation error
    And MCP server "bravo" received the forwarded MCP request

  Scenario: Protected identity slot rejects an MCP tool response missing serverIdentity
    Given the surface has managed identity enabled
    And MCP server "bravo" returns a tool result without serverIdentity
    When the caller invokes MCP tool "get_news"
    Then the response status is 422
    And the response is a "protected_identity" identity extension missing error
    And MCP server "bravo" received the forwarded MCP request

  Scenario: Schema-invalid inbound MCP identity payload is rejected before reaching the MCP server
    Given the surface has an explicit inbound identity slot for MCP
    When the caller invokes MCP tool "get_news" with a schema-invalid inbound identity payload
    Then the response status is 422
    And the response is an "inbound_identity" identity validation error
    And MCP server "bravo" was not called

  Scenario: Explicit inbound identity slot rejects a request missing the identity field
    Given the surface has an explicit inbound identity slot for MCP
    When the caller invokes MCP tool "get_news" without an inbound identity payload
    Then the response status is 422
    And the response is an "inbound_identity" identity validation error
    And MCP server "bravo" was not called

  Scenario: Explicit inbound identity slot rejects MCP metadata without the identity field
    Given the surface has an explicit inbound identity slot for MCP
    When the caller invokes MCP tool "get_news" with MCP metadata but no inbound identity field
    Then the response status is 422
    And the response is an "inbound_identity" identity validation error
    And MCP server "bravo" was not called

  Scenario: Inbound identity injection preserves unrelated MCP metadata
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload and unrelated MCP metadata field "traceId"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID
    And MCP server "bravo" received forwarded MCP metadata field "traceId" unchanged

  Scenario: Non-schema fields do not affect inbound Agent DID derivation
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    And the caller has invoked MCP tool "get_news" with a valid inbound identity payload
    When the caller invokes MCP tool "get_news" with the same inbound identity and different non-identity fields
    Then the response status is 200
    And MCP server "bravo" received two forwarded MCP requests with VPs proving the same caller Agent DID

  Scenario: Inbound identity injection forwards a VP proving the caller Agent DID to the MCP server
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: Inbound identity injection removes the raw identity payload before reaching the MCP server
    Given the surface has an explicit inbound identity slot for MCP with strip raw metadata enabled
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" did not receive the raw inbound identity payload

  Scenario: Inbound identity injection retains the raw identity payload by default
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received the raw inbound identity payload

  Scenario: Changing a selected identity field changes the caller Agent DID
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    And the caller has invoked MCP tool "get_news" with inbound identity field "softwareInfo.name" set to "planner"
    When the caller invokes MCP tool "get_news" with inbound identity field "softwareInfo.name" set to "researcher"
    Then the response status is 200
    And MCP server "bravo" received two forwarded MCP requests with VPs proving different caller Agent DIDs

  Scenario Outline: Caller Agent identity payload validation rejects invalid selected identity field "softwareInfo.name" before reaching the MCP server
    Given the surface has an explicit inbound identity slot for MCP requiring selected identity field "softwareInfo.name"
    When the caller invokes MCP tool "get_news" with inbound identity field "softwareInfo.name" <condition>
    Then the response status is 422
    And the response is an "inbound_identity" identity validation error
    And MCP server "bravo" was not called

    Examples:
      | condition                         |
      | missing                           |
      | the wrong type                    |
      | outside the configured constraint |

  Scenario: MCP onboarding derives an identity schema from an example identity payload
    Given the operator has created an MCP onboarding endpoint
    When the caller sends an MCP tool call with example identity field "softwareInfo.name" set to "planner"
    Then the response status is 200
    And the payload capture includes a derived identity schema
    And the derived identity schema includes field "softwareInfo.name"

  Scenario: A captured MCP identity schema can be used for inbound identity resolution
    Given the operator has captured an MCP identity schema with field "softwareInfo.name"
    And the operator selects identity field "softwareInfo.name" in the captured schema
    And MCP surface "alpha" uses the selected captured schema for inbound identity
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with inbound identity field "softwareInfo.name" set to "planner"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID
    And the VP received by MCP server "bravo" includes selected caller identity field "softwareInfo.name"

  Scenario: Inbound identity injection includes selected identity fields in the credential proof
    Given the surface has an explicit inbound identity slot for MCP
    And MCP server "bravo" supports tool invocation
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID
    And the VP received by MCP server "bravo" includes selected caller identity field "softwareInfo.name"
