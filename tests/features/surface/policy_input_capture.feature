Feature: Live policy input capture
  An operator who may edit surfaces and policies can listen, from the dashboard's
  Capture view, to the policy input of one surface. While they listen, the input
  and the decision of each policy evaluation on that surface reach their Capture
  view, so a policy can be written against real requests. Only the listening
  operator receives it, nothing is logged or stored, and it stops when they stop
  listening or close the dashboard.

  Background:
    Given policy input capture is turned on
    And A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy

  Scenario: The Capture view shows the policy input and decision while the operator listens
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "hello policy"

  Scenario: The Capture view names the policy each captured evaluation ran
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" running policy "BDD audited policy"

  Scenario: The Capture view shows the input and decision of a response policy
    Given the operator has added the policy definition to surface "alpha" as its response policy
    And the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 200
    And the Capture view shows the "response" policy of surface "alpha" deciding "allow" on an input showing "status_code"

  Scenario: The Capture view shows a caller's credential masked
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZGQifQ.c2lnbmF0dXJl"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "<redacted>"
    And no captured policy input of surface "alpha" contains "eyJhbGciOiJIUzI1NiJ9"

  Scenario: The Capture view masks a JWT inside a caller's message and keeps the words around it
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "my token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZGQifQ.c2lnbmF0dXJl please check"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "my token is <redacted> please check"
    And no captured policy input of surface "alpha" contains "eyJhbGciOiJIUzI1NiJ9"

  Scenario: The Capture view masks the user name and password in a URL inside a caller's message
    Given the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "fetch https://svc:s3cr3t-pw@host.example/path please"
    Then the response status is 200
    And the Capture view shows the "target" policy of surface "alpha" deciding "allow" on an input showing "fetch https://<redacted>@host.example/path please"
    And no captured policy input of surface "alpha" contains "s3cr3t-pw"

  Scenario: The Capture view shows a denying policy's decision and reason
    Given surface "alpha" has a request policy that denies with reason "only partners may call"
    And the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 403
    And the Capture view shows the "target" policy of surface "alpha" denying with reason "only partners may call"

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

  Scenario: The Capture view shows an appliance-wide policy's denial and names the policy that denied
    Given an appliance-wide surface policy "BDD appliance-wide policy" denies every request
    And the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 403
    And the Capture view shows the "appliance agent_surface" policy of surface "alpha" denying with reason "Blocked by appliance-wide policy"
    And the Capture view shows the "appliance agent_surface" policy of surface "alpha" decided by policy "BDD appliance-wide policy"

  Scenario: The Capture view shows an appliance-wide policy that fails to evaluate as an error
    Given an appliance-wide surface policy "BDD failing appliance-wide policy" fails to evaluate
    And the operator listens to the policy input of surface "alpha"
    When the caller sends an A2A message/send request to surface "alpha" with text "hello policy"
    Then the response status is 403
    And the Capture view shows the "appliance agent_surface" policy of surface "alpha" failing with error "Appliance-wide policy evaluation error"
