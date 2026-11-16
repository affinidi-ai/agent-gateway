Feature: Live policy input capture
  An operator who may edit surfaces and policies can listen, from the dashboard's
  Capture view, to the policy input of one surface. While they listen, the input
  and the decision of each policy evaluation on that surface reach their Capture
  view, so a policy can be written against real requests. Only the listening
  operator receives it, nothing is logged or stored, and it stops when they stop
  listening or close the dashboard.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy

  Scenario: The Capture view shows the policy input and decision while the operator listens
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"

  Scenario: The Capture view shows the input and decision of a response policy
    Given the operator has added the policy definition to surface "alpha" as its response policy
    And the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "response" policy of surface "alpha" deciding "allow" on an input showing "status_code"

  Scenario: The policy input is not captured unless the operator listens
    Given the operator watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows no policy input

  Scenario: The policy input is not captured once the operator stops listening
    Given the operator listens to the policy input of surface "alpha"
    And the operator has stopped listening to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows no policy input

  Scenario: Only the operator who listens receives the captured policy input
    Given the operator listens to the policy input of surface "alpha"
    And operator "olga" has the "administrator" role
    And operator "olga" watches the dashboard Capture view
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"
    And the Capture view of operator "olga" shows no policy input

  Scenario: An operator who may not edit surfaces and policies cannot listen to policy input
    Given operator "uma" has the "user" role
    When operator "uma" asks to listen to the policy input of surface "alpha"
    Then operator "uma" may not listen to policy input
