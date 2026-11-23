Feature: Trace context at an Access Point
  An Access Point continues the trace a caller names in a valid traceparent or
  X-Gateway-Trace-Id, and starts a new one otherwise. The record of the forwarded
  request carries the trace id in 32 lowercase hex, the parent span the caller
  named, and the trace source. A trace header that is not valid, or that arrived
  more than once, is treated as absent.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog
    # The gateway starts when the next step selects the audit event, and keeping
    # its log only applies at start, so every scenario keeps it.
    And the gateway keeps its log of warnings
    And the VP Audit Log keeps only audit events "request_forwarded"

  Scenario: An Access Point continues a valid caller trace
    When the caller sends a request to the surface with a traceparent set
    Then the response status is 200
    And MCP server "bravo" received a traceparent that continues the caller's trace
    And the VP Audit Log record matches the request

  Scenario: An Access Point records a hyphenated X-Gateway-Trace-Id in its written form
    When the caller sends a request to the surface with a hyphenated X-Gateway-Trace-Id
    Then the response status is 200
    And the VP Audit Log records the forwarded request under the caller's trace in its written form
    And the VP Audit Log records the forwarded request with no parent span
    And the VP Audit Log records the forwarded request with trace source "header"

  Scenario: An Access Point starts a trace when the caller's traceparent is not valid
    When the caller sends a request to the surface with an invalid traceparent
    Then the response status is 200
    And the VP Audit Log records the forwarded request under a newly minted trace
    And the VP Audit Log records the forwarded request with no parent span
    And the gateway log does not contain the caller's invalid trace

  Scenario: An Access Point starts a trace when traceparent arrives twice
    When the caller sends a request to the surface with duplicate traceparent headers
    Then the response status is 200
    And the VP Audit Log records the forwarded request under a newly minted trace
    And the VP Audit Log records the forwarded request with no parent span

  Scenario: X-Gateway-Trace-Id wins when the trace headers name different traces
    When the caller sends a request to the surface with traceparent and X-Gateway-Trace-Id naming different traces
    Then the response status is 200
    And the VP Audit Log records the forwarded request under the X-Gateway-Trace-Id trace
    And the VP Audit Log records the forwarded request with no parent span
    And the VP Audit Log records the forwarded request with trace source "header"
    And the gateway log warns that the trace headers named different traces
