Feature: Tenant ownership of Security Token Service tokens at JWT Bearer surfaces
  A JWT Bearer surface can trust the tokens the gateway's Security Token Service
  issues. It accepts such a token only when the managed connection it was issued
  to belongs to the surface's tenant or to no tenant, so one tenant's managed
  connection cannot reach another tenant's surface.

  Scenario: A token issued to another tenant's managed connection is refused at a JWT Bearer surface
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "alpha"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "/reports"
    And the surface has a policy denying callers whose source authentication failed
    And the surface trusts tokens issued by the gateway's Security Token Service
    And tenant "charlie" has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    When the caller sends a request to the surface with the token issued to agent "delta"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A token issued to the surface's own tenant's managed connection is accepted
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "alpha"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "/reports"
    And the surface has a policy denying callers whose source authentication failed
    And the surface trusts tokens issued by the gateway's Security Token Service
    And tenant "alpha" has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    When the caller sends a request to the surface with the token issued to agent "delta"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A token issued to an appliance-wide managed connection is accepted at a tenant's surface
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "alpha"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "/reports"
    And the surface has a policy denying callers whose source authentication failed
    And the surface trusts tokens issued by the gateway's Security Token Service
    And the operator has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    When the caller sends a request to the surface with the token issued to agent "delta"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A token issued to a managed connection that was since deleted is refused
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "alpha"
    And the surface requires "JWT Bearer" source authentication
    And the surface accepts JWT audience "/reports"
    And the surface has a policy denying callers whose source authentication failed
    And the surface trusts tokens issued by the gateway's Security Token Service
    And tenant "alpha" has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    And the operator has deleted the managed connection for agent "delta"
    When the caller sends a request to the surface with the token issued to agent "delta"
    Then the response status is 403
    And managed agent "bravo" was not called

  Scenario: A Transit Point refuses a token issued to another tenant's managed connection
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And the surface belongs to tenant "alpha"
    And Transit Point "outbound" routes to MCP server "echo"
    And MCP server "echo" publishes a tool catalog
    And Transit Point "outbound" authenticates its callers with JWT Bearer tokens for audience "/reports"
    And the surface trusts tokens issued by the gateway's Security Token Service
    And tenant "charlie" has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    When managed agent "example-agent" asks for available tools through Transit Point "outbound" with the token issued to agent "delta"
    Then the response status is 401
    And MCP server "echo" was not called

  Scenario: A Transit Point admits a token issued to its surface tenant's managed connection
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And the surface belongs to tenant "alpha"
    And Transit Point "outbound" routes to MCP server "echo"
    And MCP server "echo" publishes a tool catalog
    And Transit Point "outbound" authenticates its callers with JWT Bearer tokens for audience "/reports"
    And the surface trusts tokens issued by the gateway's Security Token Service
    And tenant "alpha" has a managed connection for agent "delta" allowing audience "/reports"
    And agent "delta" holds an identity assertion for subject "did:example:user"
    And agent "delta" has exchanged the identity assertion for a token scoped to audience "/reports"
    When managed agent "example-agent" asks for available tools through Transit Point "outbound" with the token issued to agent "delta"
    Then the response status is 200
    And MCP server "echo" received MCP method "tools/list"
