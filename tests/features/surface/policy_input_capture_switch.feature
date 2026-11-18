Feature: Policy input capture is off until an administrator turns it on
  Listening to a surface's policy input needs the policy_input_capture feature flag,
  which is off by default. While it is off, the gateway refuses to listen and
  captures nothing, and turning it off stops every listen at the next keep-alive check.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy

  Scenario: An operator may not listen to policy input while policy input capture is turned off
    Given policy input capture is turned off
    When the operator asks to listen to the policy input of surface "alpha"
    Then the operator may not listen to policy input because policy input capture is turned off

  Scenario: An operator receives no policy input while policy input capture is turned off
    Given policy input capture is turned off
    And the operator has asked to listen to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows no policy input

  Scenario: Turning policy input capture off stops a listen at the next keep-alive check
    Given policy input capture is turned on
    And the operator listens to the policy input of surface "alpha"
    When an administrator turns policy input capture off
    Then the operator is told by the next keep-alive check that listening to surface "alpha" stopped because policy input capture is turned off
