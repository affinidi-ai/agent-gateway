Feature: Trace context along the request path
  The Managed Agent receives the trace of the request it serves, so the calls
  it makes through a Transit Point can be tied to that request.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And Transit Point "tools" routes to MCP server "charlie"
    And MCP server "charlie" publishes a tool catalog
    And Transit Point "tools" requires a transit token
    And the VP Audit Log keeps only audit events "request_forwarded, transit_request_forwarded"

  Scenario: The Managed Agent receives the trace of the request it serves
    When the caller sends a request to the surface with a traceparent set
    Then the response status is 200
    And managed agent "bravo" received a traceparent that continues the caller's trace
    And managed agent "bravo" received the caller's trace in X-Gateway-Trace-Id

  Scenario: A Transit Point request is tied to the Access Point request it serves
    Given the caller has sent a request to the surface with a traceparent set
    And managed agent "bravo" holds the transit token the Access Point gave it
    When managed agent "bravo" asks for available tools through Transit Point "tools" with its transit token and the trace headers it received
    Then the response status is 200
    And MCP server "charlie" received no trace header
    And the VP Audit Log ties the Transit Point request to the Access Point request
    And the VP Audit Log records the Transit Point request with trace source "transit_token"

  Scenario: A Transit Point request is in the Access Point request's trace when the agent forwards no trace header
    Given the caller has sent a request to the surface with a traceparent set
    And managed agent "bravo" holds the transit token the Access Point gave it
    When managed agent "bravo" asks for available tools through Transit Point "tools" with its transit token and no trace header
    Then the response status is 200
    And MCP server "charlie" received no trace header
    And the VP Audit Log records the Transit Point request under the trace of the Access Point request
    And the VP Audit Log records the Transit Point request with no parent span
