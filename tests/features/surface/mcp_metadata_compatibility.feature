Feature: Backward-compatible MCP metadata
  Operators can adopt canonical MCP metadata without changing existing integrations by default.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation

  Scenario Outline: Inbound identity proof uses the selected MCP metadata format
    Given the surface has an explicit inbound identity slot for MCP
    And the surface uses "<format>" MCP metadata output
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received MCP metadata key "<key>" only in "params._meta"
    And MCP server "bravo" did not receive MCP _meta key "<obsolete_key>"
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID

    Examples:
      | format        | key                                                              | obsolete_key                                                     |
      | compatibility | https://fabric.affinidi.io/extensions/agent-identity-binding/v1   | io.affinidi.fabric/agent-identity-binding                          |
      | canonical     | io.affinidi.fabric/agent-identity-binding                          | https://fabric.affinidi.io/extensions/agent-identity-binding/v1   |

  Scenario: Canonical response credentials use result metadata and retain raw identity by default
    Given the surface has managed identity enabled
    And MCP server "bravo" includes an agent-identity extension in responses
    And the surface uses "canonical" MCP metadata output
    When the caller invokes MCP tool "get_news"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And the MCP response contains metadata key "io.affinidi.fabric/agent-identity-credential" only in "result._meta"
    And the MCP response does not contain metadata key "https://fabric.affinidi.io/extensions/agent-identity-credential/v1"
    And the MCP response contains the raw serverIdentity payload

  Scenario: Canonical output accepts historical top-level raw identity input
    Given the surface has an explicit inbound identity slot for MCP with strip raw metadata enabled
    And the surface uses "canonical" MCP metadata output
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload in "top-level" metadata
    Then the response status is 200
    And MCP server "bravo" received MCP metadata key "io.affinidi.fabric/agent-identity-binding" only in "params._meta"
    And MCP server "bravo" received the forwarded MCP request with a VP proving the caller Agent DID
    And MCP server "bravo" did not receive the raw inbound identity payload

  Scenario: Canonical custom metadata preserves ordinary caller metadata
    Given the surface injects custom metadata key "tenant" value "acme" into "meta"
    And the surface uses "canonical" MCP metadata output
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":"metadata","method":"tools/call","params":{"name":"get_news","arguments":{},"_meta":{"progressToken":7}},"_meta":{"traceId":"caller-trace"}}
      """
    Then the response status is 200
    And MCP server "bravo" received MCP metadata key "tenant" only in "params._meta"
    And MCP server "bravo" received MCP _meta key "tenant" with value "acme"
    And MCP server "bravo" received forwarded MCP field "params._meta.progressToken" unchanged
    And MCP server "bravo" received MCP _meta key "traceId" with value "caller-trace"

  Scenario: Malformed canonical metadata is not replaced by historical metadata
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":"malformed-meta","method":"tools/call","params":{"name":"get_news","_meta":null},"_meta":{"tenant":"fallback"}}
      """
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32602
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: Conflicting identity aliases are rejected before reaching the MCP server
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":"conflicting-meta","method":"tools/call","params":{"name":"get_news","_meta":{"io.affinidi.fabric/agent-identity-credential":{"did":"did:example:one"},"https://fabric.affinidi.io/extensions/agent-identity-credential/v1":{"did":"did:example:two"}}}}
      """
    Then the response status is 400
    And the MCP response is a JSON-RPC error with code -32602
    And the MCP response id matches the request id
    And MCP server "bravo" was not called

  Scenario: An older client update does not reset canonical metadata output
    Given the surface has an explicit inbound identity slot for MCP
    And the surface uses "canonical" MCP metadata output
    And the operator has updated the surface description without a metadata output preference
    When the caller invokes MCP tool "get_news" with a valid inbound identity payload
    Then the response status is 200
    And MCP server "bravo" received MCP metadata key "io.affinidi.fabric/agent-identity-binding" only in "params._meta"
    And MCP server "bravo" did not receive MCP _meta key "https://fabric.affinidi.io/extensions/agent-identity-binding/v1"
