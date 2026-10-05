Feature: A2A surface HTTP transport contract
  The gateway faithfully forwards HTTP requests and responses over an A2A
  surface without mutating content — bodies, query strings, headers, status
  codes, and response headers are relayed exactly as sent unless an explicit
  surface feature requires transformation.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: POST JSON body reaches the target unchanged
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe-marker-abc"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the request body {"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe-marker-abc"}],"messageId":"bdd-message"}}}

  Scenario: Happy-path JSON response body and content-type are relayed to the caller unchanged
    When the caller sends a request to the surface
    Then the response status is 200
    And the response content type is "application/json"
    And the response body matches managed agent "bravo" response

  Scenario: Repeated query keys are forwarded unchanged
    When the caller sends a request to the surface path "/smoke/items?tag=a&tag=b"
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/items?tag=a&tag=b"

  Scenario: URL-encoded characters in the query string are forwarded unchanged
    When the caller sends a request to the surface path "/smoke/search?q=hello%20world&lang=en%2FUS"
    Then the response status is 200
    And managed agent "bravo" received the forwarded path "/search?q=hello%20world&lang=en%2FUS"

  Scenario: An unknown gateway route returns 404 and does not reach the target
    When the caller sends a request to the unknown path "/no-such-route/foo"
    Then the response status is 404
    And managed agent "bravo" was not called

  Scenario: Caller headers are forwarded to the target
    When the caller sends a request to the surface with extra headers
      | x-custom-app-header | my-value  |
      | x-request-id        | req-12345 |
    Then managed agent "bravo" received header "x-custom-app-header" with value "my-value"
    And managed agent "bravo" received header "x-request-id" with value "req-12345"

  Scenario: Hop-by-hop headers sent by the caller are not forwarded to the target
    When the caller sends a request to the surface with extra headers
      | connection        | keep-alive |
      | transfer-encoding | chunked    |
      | authorization     | Bearer secret-token |
    Then managed agent "bravo" did not receive header "connection"
    And managed agent "bravo" did not receive header "transfer-encoding"
    And managed agent "bravo" did not receive header "authorization"

  Scenario Outline: Non-2xx target status codes are relayed to the caller unchanged
    Given managed agent "bravo" is failing with status <status>
    When the caller sends a request to the surface
    Then the response status is <status>
    And managed agent "bravo" received the forwarded request

    Examples:
      | status |
      | 400    |
      | 404    |
      | 422    |
      | 500    |

  Scenario: Target response headers are relayed to the caller
    Given managed agent "bravo" responds with header "x-target-trace" set to "trace-abc"
    When the caller sends a request to the surface
    Then the response status is 200
    And the response includes header "x-target-trace" with value "trace-abc"

  Scenario: Target connection failure returns a gateway-side error, not a target error
    Given managed agent "bravo" is unreachable
    When the caller sends a request to the surface
    Then the response status is a gateway error
    And the response body is a gateway error message
    And managed agent "bravo" was not called

  Scenario: Concurrent requests each reach the target exactly once
    When 3 callers send requests to the surface concurrently
    Then managed agent "bravo" received exactly 3 requests

  Scenario: Sequential requests each reach the target exactly once
    When 3 callers send requests to the surface sequentially
    Then managed agent "bravo" received exactly 3 requests
