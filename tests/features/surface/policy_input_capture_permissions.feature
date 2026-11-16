Feature: Listening to policy input needs both surfaces.edit and policies.edit
  Listening to a surface's policy input in the dashboard's Capture view needs
  surfaces.edit and policies.edit. An operator whose role holds only one of them
  may not listen and receives nothing.

  Scenario: An operator who may edit surfaces and policies receives the policy input they listen to
    Given the "poweruser" role is granted "surfaces.edit"
    And the "poweruser" role is granted "policies.edit"
    And A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy
    And operator "pete" has the "poweruser" role
    And operator "pete" listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view of operator "pete" shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"

  Scenario: An operator who may edit surfaces but not policies may not listen to policy input
    Given the "poweruser" role is granted "surfaces.edit"
    And A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy
    And the operator listens to the policy input of surface "alpha"
    And operator "pete" has the "poweruser" role
    And operator "pete" has asked to listen to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then operator "pete" may not listen to policy input
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"
    And the Capture view of operator "pete" shows no policy input

  Scenario: An operator who may edit policies but not surfaces may not listen to policy input
    Given the "poweruser" role is granted "policies.edit"
    And A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy
    And the operator listens to the policy input of surface "alpha"
    And operator "pete" has the "poweruser" role
    And operator "pete" has asked to listen to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then operator "pete" may not listen to policy input
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"
    And the Capture view of operator "pete" shows no policy input
