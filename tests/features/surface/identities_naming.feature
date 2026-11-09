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

  Scenario: A managed agent shared by several surfaces is listed once
    Given A2A surfaces "oxygen" and "helium" exist with managed agent "bravo" as their target
    And surfaces "oxygen" and "helium" have managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller has sent a request to surface "oxygen"
    And the caller has sent a request to surface "helium"
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Identities dashboard shows one Managed Agent identity without a name
    And the Managed Agent identity belongs to surfaces "helium" and "oxygen"

  Scenario: A surface where the managed agent was only a caller is not listed
    Given A2A surfaces "oxygen" and "delta" exist with managed agents "bravo" and "charlie" as their targets
    And surface "oxygen" takes its managed identity from API key "bravo-key"
    And surface "delta" identifies its callers by API key "bravo-key"
    And managed agent "bravo" has called surface "oxygen"
    And managed agent "bravo" has called surface "delta" with API key "bravo-key"
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
