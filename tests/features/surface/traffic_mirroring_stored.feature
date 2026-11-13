Feature: Stored surfaces that mirror traffic
  A surface stored with a mirror endpoint the admin API would now refuse still
  loads and serves its callers. The gateway refuses to send the copy, and the
  surface cannot be saved again until its mirror endpoint is corrected.

  Scenario: A stored surface that mirrors traffic to a cloud metadata service still serves its callers
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored with a public Access Point
    And the surface is stored with a mirror to "http://169.254.169.254/latest/meta-data/"
    When the caller sends a request to the surface without an API key
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A stored surface whose mirror endpoint is refused cannot be saved again
    Given an A2A surface targeting managed agent "bravo"
    And the surface is stored with a public Access Point
    And the surface is stored with a mirror to "http://169.254.169.254/latest/meta-data/"
    When the operator renames the stored surface
    Then the admin API response status is 400
    And the admin API error response mentions "target.networking.mirror.endpoint"
