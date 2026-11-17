Feature: Live policy input capture of the gateway-level policy
  The gateway-level policy runs on every request before the surface's own policy.
  While an operator listens to a surface's policy input, the Capture view also shows
  the gateway-level policy's evaluations of requests to that surface, in its own
  gateway slot, and in a gateway outbound slot for the calls a managed agent sends
  through a Transit Point.

  Background:
    Given gateway "gateway-1" with outbound listener
    And gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
    And surface "alpha" uses path "/example"

  Scenario: The Capture view shows the gateway-level policy allowing a request
    Given gateway "gateway-1" has gateway-level policy that allows inbound requests only to "/target/allowed"
    And the operator listens to the policy input of surface "alpha"
    When the caller sends A2A request to the surface path "/example/target/allowed/path" in gateway "gateway-1"
    Then the response status is 200
    And the Capture view shows the "gateway" policy of surface "alpha" deciding "allow" on an input showing "/target/allowed/path"

  Scenario: The Capture view shows the gateway-level policy denying a request and names the policy that denied
    Given gateway "gateway-1" has gateway-level policy "bdd-gateway-path-policy" that allows inbound requests only to "/target/allowed"
    And the operator listens to the policy input of surface "alpha"
    When the caller sends A2A request to the surface path "/example/target/unallowed/path" in gateway "gateway-1"
    Then the response status is 403
    And the Capture view shows the "gateway" policy of surface "alpha" deciding "deny" on an input showing "/target/unallowed/path"
    And the Capture view shows the "gateway" policy of surface "alpha" decided by policy "bdd-gateway-path-policy"

  Scenario: The Capture view shows the gateway-level policy evaluating a call sent through a Transit Point
    Given external agent "agent-external"
    And surface "alpha" has direct A2A transit point "tr1" to agent "agent-external"
    And transit point "tr1" uses path "/example/forward/foo"
    And gateway "gateway-1" has a gateway-level policy that allows every request
    And the operator listens to the policy input of surface "alpha"
    When the caller sends A2A request to the surface path "/example/foo" in gateway "gateway-1"
    Then the response status is 200
    And the Capture view shows the "gateway outbound" policy of surface "alpha" deciding "allow" on an input showing "/example/forward/foo"
