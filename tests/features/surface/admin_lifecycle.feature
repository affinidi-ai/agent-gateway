Feature: Surface creation through the admin API
  An operator can create a surface through the admin API, and the gateway
  rejects invalid configuration while created surfaces serve caller traffic.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target

  Scenario: Creating a surface returns the created surface record
    When the operator creates a valid surface for route "/example"
    Then the admin API response status is 201
    And the admin API response includes a surface id

  Scenario: A created surface serves caller traffic
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And the response body matches managed agent "bravo" response
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" received the forwarded path "/foo"

  Scenario: Invalid surface creation is rejected
    When the operator attempts to create a surface for route "/example" with invalid configuration
    Then the admin API response status is 400
    And the admin API error response mentions "target.endpoint is required"
    And the admin API response does not include a surface id

  Scenario: A rejected surface creation does not activate routing
    Given the operator has attempted to create a surface for route "/example" with invalid configuration
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 404
    And managed agent "bravo" was not called
