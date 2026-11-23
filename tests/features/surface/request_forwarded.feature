Feature: Forwarded requests in the VP Audit Log
  An Access Point records each request it hands to its Target as one
  request_forwarded record, whether or not a policy runs. The record names the
  caller only when source authentication verified it. A request refused before
  it is forwarded is not recorded as forwarded.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog

  Scenario: A forwarded request is recorded once with its caller
    Given the surface requires "API Key" source authentication
    And the VP Audit Log keeps only audit events "request_forwarded"
    When the caller sends a request to the surface with a valid API key and a traceparent set
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And the VP Audit Log records the forwarded request once
    And the VP Audit Log record matches the request

  Scenario: A refused request is not recorded as forwarded
    Given the MCP surface has a request policy that denies all requests
    And the VP Audit Log keeps only audit events "request_forwarded"
    When the caller sends a request to the surface with a traceparent set
    Then the response status is 403
    And MCP server "bravo" was not called
    And the VP Audit Log records no forwarded request
