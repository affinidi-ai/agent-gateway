Feature: Identity names on the Identities dashboard
  The Identities dashboard names each identity after where it came from. A
  managed agent identity takes the name in its target's Agent Card on A2A and AP2
  surfaces, and the name of its surface otherwise. An external caller is
  never named after a surface; without a verified agent name or an Agent Card
  name it is shown by its DID alone.

  Scenario: A managed agent identity without an Agent Card name is named after its surface
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Identities dashboard shows a Managed Agent identity named "oxygen"
    And the Managed Agent identity belongs to surface "oxygen"

  @wip
  Scenario: A VP-verified external caller is listed without a name
    Given an A2A surface targeting managed agent "bravo"
    And the caller has sent a request to the surface with a verified agent identity presentation
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Identities dashboard shows an External Caller identity for the caller
    And the External Caller identity has no name
