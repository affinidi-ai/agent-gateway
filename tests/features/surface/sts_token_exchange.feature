Feature: Security Token Service token exchange
  An agent exchanges an identity assertion at the gateway token endpoint for a
  short-lived, audience-scoped token. The operator authorizes each agent through
  a managed connection, and the gateway records the delegating agent in the
  issued token.

  Scenario: An authorized agent exchanges an identity assertion for a scoped token
    Given the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" exchanges the identity assertion for a token scoped to audience "/reports"
    Then the response status is 200
    And the issued token names subject "did:example:user"
    And the issued token names agent "alpha" as the delegating actor
    And the issued token is scoped to audience "/reports"

  Scenario: An agent without a managed connection cannot exchange tokens
    Given the operator has no managed connection for agent "alpha"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" exchanges the identity assertion for a token
    Then the response status is 401
    And the response is an "invalid_client" error
    And no token is issued

  Scenario: An agent cannot obtain a token for an audience outside its managed connection
    Given the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" exchanges the identity assertion for a token scoped to audience "/payroll"
    Then the response status is 400
    And the response is an "invalid_target" error
    And no token is issued

  Scenario: An agent cannot obtain an ID-JAG unless its managed connection permits it
    Given the operator has a managed connection for agent "alpha" that cannot issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" requests an ID-JAG for audience "/reports"
    Then the response status is 400
    And the response is an "unauthorized_client" error
    And no token is issued

  Scenario: An authorized agent obtains an ID-JAG for a downstream service
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" requests an ID-JAG for audience "/reports"
    Then the response status is 200
    And the issued token is an ID-JAG bound to audience "/reports"

  Scenario: An authorized agent redeems an ID-JAG for a scoped access token
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And agent "alpha" has obtained an ID-JAG redeemable at the gateway
    When agent "alpha" redeems the ID-JAG for a token scoped to audience "/reports"
    Then the response status is 200
    And the issued token names subject "did:example:user"
    And the issued token is scoped to audience "/reports"

  Scenario: A redeemed ID-JAG cannot be redeemed a second time
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And agent "alpha" has obtained an ID-JAG redeemable at the gateway
    And agent "alpha" has redeemed the ID-JAG for a token scoped to audience "/reports"
    When agent "alpha" redeems the same ID-JAG again
    Then the response status is 400
    And the response is an "invalid_grant" error
    And no token is issued

  Scenario: An agent cannot redeem an ID-JAG issued to another agent
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG
    And the operator has a managed connection for agent "beta" that can issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And agent "alpha" has obtained an ID-JAG redeemable at the gateway
    When agent "beta" redeems the ID-JAG issued to agent "alpha"
    Then the response status is 400
    And the response is an "invalid_grant" error
    And no token is issued

  Scenario: Redeeming an ID-JAG cannot widen its granted scope
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG allowing scopes "reports.read reports.write"
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And agent "alpha" has obtained an ID-JAG granting scope "reports.read"
    When agent "alpha" redeems the ID-JAG requesting scope "reports.read reports.write"
    Then the response status is 200
    And the issued token grants only scope "reports.read"

  Scenario: A managed connection without a client secret cannot exchange tokens
    Given the operator has a managed connection for agent "alpha" with no client secret
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    When agent "alpha" exchanges the identity assertion for a token
    Then the response status is 401
    And the response is an "invalid_client" error
    And no token is issued

  Scenario: An agent cannot exchange an ID-JAG for a token
    Given the operator has a managed connection for agent "alpha" that can issue ID-JAG
    And the operator has a managed connection for agent "beta" that can issue ID-JAG
    And agent "alpha" holds an identity assertion for subject "did:example:user"
    And agent "alpha" has obtained an ID-JAG redeemable at the gateway
    When agent "beta" exchanges the ID-JAG issued to agent "alpha" for a token
    Then the response status is 400
    And the response is an "invalid_request" error
    And no token is issued

  Scenario: An agent exchanges a token the gateway issued without outliving the identity assertion
    Given the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user" that expires in 60 seconds
    And agent "alpha" has exchanged the identity assertion for a token scoped to audience "/reports"
    When agent "alpha" exchanges the issued token for a token scoped to audience "/reports"
    Then the response status is 200
    And the issued token names subject "did:example:user"
    And the issued token expires no later than the identity assertion of agent "alpha"

  Scenario: An exchanged token does not outlive the identity assertion it was exchanged from
    Given the operator has a managed connection for agent "alpha" allowing audience "/reports"
    And agent "alpha" holds an identity assertion for subject "did:example:user" that expires in 60 seconds
    When agent "alpha" exchanges the identity assertion for a token scoped to audience "/reports"
    Then the response status is 200
    And the issued token expires no later than the identity assertion of agent "alpha"

