Feature: Trust Recorder status on the Identities dashboard
  The gateway keeps the last known outcome of the Trust Recorder for each Managed
  Agent identity and shows it on the Identities dashboard and on the surface.
  "Recorded" means the recorder's last outcome, not a live check of the trust
  registry. A surface without a Trust Recorder shows no status.

  Scenario: A Trust Recorder whose trust registry does not exist is shown as skipped
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the surface has a Trust Recorder for trust registry "missing-registry" with issuer "did:web:example.com:issuer"
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then within ten seconds the Managed Agent identity shows Trust Recorder status "skipped" because "registry_not_found"
    And within ten seconds the Trust Recorder status of surface "oxygen" is "skipped"

  Scenario: A Trust Recorder that needs the surface Issuer is shown as skipped when the surface has none
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the surface has a Trust Recorder for trust registry "missing-registry" with issuer "did:web:example.com:issuer"
    And the Trust Recorder for trust registry "missing-registry" takes the surface Issuer as its authority
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then within ten seconds the Managed Agent identity shows Trust Recorder status "skipped" because "no_surface_issuer"

  Scenario: A Trust Recorder whose trust registry is not connected is shown as skipped
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller has sent a request to the surface
    And surface "oxygen" later gets a Trust Recorder for an unconnected trust registry with issuer "did:web:example.com:issuer"
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then within ten seconds the Managed Agent identity shows Trust Recorder status "skipped" because "registry_not_connected"

  Scenario: A Trust Recorder added after the agent was first seen shows not attempted yet
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller has sent a request to the surface
    And surface "oxygen" later gets a Trust Recorder for an unconnected trust registry with issuer "did:web:example.com:issuer"
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity shows Trust Recorder status "not_attempted"

  Scenario: A surface without a Trust Recorder shows no recorder status
    Given A2A surface "oxygen" is defined for route "/oxygen" with managed agent "bravo" as its target
    And the surface has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And the caller has sent a request to the surface
    When the operator reads the Identities dashboard
    Then the admin API response status is 200
    And the Managed Agent identity shows no Trust Recorder status
