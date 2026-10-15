Feature: Rate limiting is audited
  A request the Access Point refuses because the surface's rate limit is
  reached is recorded in the VP Audit Log.

  Scenario: A request over the surface rate limit is refused and recorded
    Given an A2A surface targeting managed agent "bravo"
    And the surface admits 1 request per minute
    And the VP Audit Log keeps every audit event
    And the surface rate limit is reached
    When the caller sends a request to the surface
    Then the response status is 429
    And the response carries a non-empty "retry-after" header
    And managed agent "bravo" received exactly 1 request
    And the VP Audit Log records the surface rate limit refusal
