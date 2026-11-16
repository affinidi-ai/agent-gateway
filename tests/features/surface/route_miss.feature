Feature: Requests on a route no surface serves
  A request under a registered route that no surface serves gets one
  protocol-neutral refusal, whether the surface never existed, is disabled or
  was deleted.

  Scenario: A route that never had a surface answers with the protocol-neutral refusal
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 404
    And the response says only that no surface is served at "/example/foo"
