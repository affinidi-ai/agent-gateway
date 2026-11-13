Feature: Traffic mirroring endpoints
  A surface that mirrors traffic copies each request to its mirror endpoint. The
  endpoint gets the Target's cloud-metadata guard: an http or https URL with no
  credentials that does not name a cloud provider's metadata service, whether the
  surface or one of its variants sets it. The copy is not redirected. Loopback
  and private addresses stay allowed.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target

  Scenario Outline: A surface that mirrors traffic to a cloud metadata service is refused
    When the operator attempts to create a surface for route "/example" that mirrors traffic to "<endpoint>"
    Then the admin API response status is 400
    And the admin API error response mentions "target.networking.mirror.endpoint"

    Examples:
      | endpoint                                                   |
      | http://169.254.169.254/latest/meta-data/                   |
      | http://169.254.170.2/v2/credentials                        |
      | http://metadata.google.internal/computeMetadata/v1/        |
      | http://[::ffff:169.254.169.254]/                           |
      | http://[fd00:ec2::254]/                                    |

  Scenario: A surface that mirrors traffic to a URL that is not http or https is refused
    When the operator attempts to create a surface for route "/example" that mirrors traffic to "ftp://mirror.example.com/copy"
    Then the admin API response status is 400
    And the admin API error response mentions "target.networking.mirror.endpoint"

  Scenario: A surface that mirrors traffic to a private network address is saved
    When the operator attempts to create a surface for route "/example" that mirrors traffic to "http://10.1.2.3/copy"
    Then the admin API response status is 201

  Scenario: A variant that mirrors traffic to a cloud metadata service is refused
    When the operator attempts to create a surface for route "/example" with variant "shadow" that mirrors traffic to "http://169.254.169.254/latest/meta-data/"
    Then the admin API response status is 400
    And the admin API error response mentions "Variant 'shadow'"
    And the admin API error response mentions "target.networking.mirror.endpoint"

  Scenario: A mirrored request reaches both the Target and the mirror
    Given a mirror endpoint "sink" is available
    And a surface for route "/example" mirrors every request to the mirror endpoint "sink"
    When the caller sends a request to the surface path "/example"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And the mirror endpoint "sink" received the forwarded request

  Scenario: A redirect from the mirror endpoint is not followed
    Given a mirror endpoint "sink" is available
    And the mirror endpoint "sink" answers every request with a redirect to managed agent "bravo"
    And a surface for route "/example" mirrors every request to the mirror endpoint "sink"
    When the caller sends a request to the surface path "/example"
    Then the response status is 200
    And the mirror endpoint "sink" received the forwarded request
    And managed agent "bravo" received the forwarded request

  Scenario: A surface updated to mirror traffic to a cloud metadata service is refused
    Given the operator has created the surface for route "/example"
    When the operator updates the surface to mirror traffic to "http://169.254.169.254/latest/meta-data/"
    Then the admin API response status is 400
    And the admin API error response mentions "target.networking.mirror.endpoint"

  Scenario: A surface patched to mirror traffic to a cloud metadata service is refused
    Given the operator has created the surface for route "/example"
    When the operator patches the surface to mirror traffic to "http://metadata.google.internal/computeMetadata/v1/"
    Then the admin API response status is 400
    And the admin API error response mentions "target.networking.mirror.endpoint"

  Scenario: A surface patched to mirror traffic to a private network address is saved
    Given the operator has created the surface for route "/example"
    When the operator patches the surface to mirror traffic to "http://10.1.2.3/copy"
    Then the admin API response status is 200
