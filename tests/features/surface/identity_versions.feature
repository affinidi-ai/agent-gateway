Feature: Identity versions on the Identities dashboard
  The gateway records which Identity slot produced each managed identity. A
  Transit Point with a managed identity of its own has a slot of its own; a
  Transit Point that inherits the surface's managed identity shares the
  protected slot. A managed identity taken from a stored client certificate or
  API key gets a new version when that credential is renewed or edited. The
  dashboard row counts those versions, and Version History lists them.

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
    And the Version History of the Managed Agent identity shows the certificate fingerprint it replaced

  Scenario: Editing the stored API key behind the protected slot adds an identity version
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And surface "alpha" takes its managed identity from API key "bravo-key"
    And the caller has sent a request to the surface
    And the value of API key "bravo-key" has been changed
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity has 2 versions in the protected slot
    And the Version History of the Managed Agent identity shows a credential update without field changes
