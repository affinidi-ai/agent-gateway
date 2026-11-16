Feature: Live policy input capture of a Transit Point
  A request a managed agent sends through a Transit Point is evaluated by the
  Transit Point's policy. An operator listening to the surface's policy input sees
  that evaluation in the Capture view under the Transit Point's alias, with the
  policy it ran.

  Background:
    Given A2A surface "alpha" is defined for route "/example" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tr1" to external agent "charlie"
    And Transit Point "tr1" has a policy that allows every request

  Scenario: The Capture view shows a Transit Point policy's decision and the policy it ran
    Given the operator listens to the policy input of surface "alpha"
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 200
    And the Capture view shows the "transit tr1" policy of surface "alpha" running policy "bdd-transit-allow-tr1"
