Feature: Identity versions on the Identities dashboard
  The Identities dashboard groups a managed agent's identity versions by the
  Identity slot that produced them. A Transit Point with a managed identity of
  its own has a slot of its own; a Transit Point that inherits the surface's
  managed identity shares the protected slot. A managed identity taken from a
  client certificate gets a new version when the certificate is renewed.

  Scenario: A Transit Point with its own managed identity records it under its own slot
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And Transit Point "tr1" has a managed identity of its own
    And managed agent "bravo" has sent a request with the agent-identity extension through Transit Point "tr1"
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity is in the slot of Transit Point "tr1"

  Scenario: A Transit Point that inherits the surface's managed identity records it under the protected slot
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And the surface has managed identity enabled
    And Transit Point "tr1" presents the managed agent's identity to its destination
    And managed agent "bravo" has sent a request with the agent-identity extension through Transit Point "tr1"
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity is in the protected slot

  Scenario: Renewing the client certificate behind the protected slot adds an identity version
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And the surface takes its protected identity from client certificate "bravo-cert"
    And the caller has sent a request to the surface
    And client certificate "bravo-cert" has been renewed
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity has 2 versions in the protected slot
