Feature: Policy input captures are recorded in the VP Audit Log
  Each time an operator starts or stops listening to a surface's policy input, the
  VP Audit Log records who listened to which surface and, for a stop, why it ended,
  so watching live caller data is never silent.

  Background:
    Given policy input capture is turned on
    And the VP Audit Log keeps every audit event
    And A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target

  Scenario: Starting to listen to a surface's policy input is recorded
    When the operator listens to the policy input of surface "alpha"
    Then the VP Audit Log records that the operator started capturing the policy input of surface "alpha"

  Scenario: Stopping listening to a surface's policy input is recorded with its reason
    Given the operator listens to the policy input of surface "alpha"
    When the operator stops listening to the policy input of surface "alpha"
    Then the VP Audit Log records that the operator's capture of the policy input of surface "alpha" ended with reason "stopped"

  Scenario: A listen stopped because policy input capture was turned off is recorded with its reason
    Given the operator listens to the policy input of surface "alpha"
    When an administrator turns policy input capture off
    Then the operator is told by the next keep-alive check that listening to surface "alpha" stopped because policy input capture is turned off
    And the VP Audit Log records that the operator's capture of the policy input of surface "alpha" ended with reason "turned_off"
