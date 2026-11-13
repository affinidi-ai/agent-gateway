Feature: Policy input capture on demand
  An operator who may edit surfaces and policies can switch on, for up to 60
  minutes, policy input capture on one surface. While it is on, the dashboard's
  Capture view receives the input and the decision of each policy evaluation on
  that surface, so a policy can be written against real requests. Nothing is
  logged. It is off until switched on, stops by itself and can be switched off at
  any time.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy

  Scenario: The Capture view shows the policy input and decision while capture is on
    Given the operator has switched on policy input capture for surface "alpha" for 5 minutes
    And the operator watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"

  Scenario: The Capture view shows the input and decision of a response policy
    Given the operator has added the policy definition to surface "alpha" as its response policy
    And the operator has switched on policy input capture for surface "alpha" for 5 minutes
    And the operator watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "response" policy of surface "alpha" deciding "allow" on an input showing "status_code"

  Scenario: The policy input is not captured unless capture was switched on
    Given the operator watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows no policy input

  Scenario: The policy input is not captured once capture is switched off
    Given the operator has switched on policy input capture for surface "alpha" for 5 minutes
    And the operator has switched off policy input capture for surface "alpha"
    And the operator watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows no policy input

  Scenario: An operator who may not edit surfaces and policies does not receive captured policy input
    Given the operator has switched on policy input capture for surface "alpha" for 5 minutes
    And operator "uma" has the "user" role
    And operator "uma" watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view of operator "uma" shows no policy input

  Scenario: Switching on policy input capture sets when it stops
    When the operator switches on policy input capture for surface "alpha" for 15 minutes
    Then the admin API response status is 200
    And surface "alpha" captures its policy input for at most 15 minutes

  Scenario: Policy input capture cannot be switched on for more than 60 minutes
    When the operator switches on policy input capture for surface "alpha" for 61 minutes
    Then the admin API response status is 400

  Scenario: An operator who may not edit surfaces and policies cannot switch on policy input capture
    Given operator "uma" has the "user" role
    When operator "uma" switches on policy input capture for surface "alpha" for 5 minutes
    Then the admin API response status is 403

  Scenario: Saving a surface does not change when its policy input capture stops
    Given the operator has switched on policy input capture for surface "alpha" for 5 minutes
    When the operator saves surface "alpha" with a policy input capture end of its own
    Then the admin API response status is 200
    And surface "alpha" captures its policy input for at most 5 minutes
