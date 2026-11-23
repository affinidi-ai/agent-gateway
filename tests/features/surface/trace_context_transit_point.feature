Feature: Trace context along the request path
  The Managed Agent receives the trace of the request it serves, so the calls
  it makes through a Transit Point can be tied to that request.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: The Managed Agent receives the trace of the request it serves
    When the caller sends a request to the surface with a traceparent set
    Then the response status is 200
    And managed agent "bravo" received a traceparent that continues the caller's trace
    And managed agent "bravo" received the caller's trace in X-Gateway-Trace-Id
