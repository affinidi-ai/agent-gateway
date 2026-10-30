Feature: MCP authorization server discovery
  An MCP surface whose source authentication takes JWT Bearer tokens can publish
  protected resource metadata (RFC 9728) that names the authorization server
  of its JWT verification strategy, or the one it lists, so an MCP client finds where to get a token without manual
  configuration. The metadata lists the scopes the surface requires and then
  the scopes it advertises. A caller without a valid token is answered with a
  challenge that points at that metadata, and names the scopes the surface
  requires, if any. A token's scopes are read from its scope or scp claim, and
  a token short of a required scope is refused with 403 before policy.
  Only tokens issued for the surface itself are accepted. A surface that does
  not publish it behaves as before.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface requires "JWT Bearer" source authentication

  Scenario: An MCP surface publishes its protected resource metadata
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the response includes header "cache-control" with value "no-store"
    And the protected resource metadata names the surface as the resource
    And the protected resource metadata names authorization server "https://idp.example/realms/agents"
    And the protected resource metadata lists scope "tools"

  Scenario: An MCP surface that publishes the authorization server of its source authentication names its strategy's issuer and its required scopes
    Given the surface publishes the authorization server of its source authentication
    And the surface requires scopes "tools.call"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the protected resource metadata names the surface Access Point URL as its resource
    And the protected resource metadata lists the authorization server of the surface
    And the protected resource metadata lists scopes "tools.call"

  Scenario: A caller without a token is challenged before a gateway policy that denies every request
    Given the surface publishes the authorization server of its source authentication
    And the surface requires scopes "tools.call"
    And the gateway has a gateway-level policy that denies every request
    When the caller asks the MCP surface for available tools without a token
    Then the response status is 401
    And the response challenges the caller to authorize for scopes "tools.call"
    And MCP server "bravo" was not called

  Scenario: The protected resource metadata lists the required scopes before the advertised ones
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface requires scopes "tools.call tools"
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 200
    And the protected resource metadata lists scopes "tools.call tools"

  Scenario: A caller without a token is told where to get one
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the VP Audit Log keeps every audit event
    When the caller asks the MCP surface for available tools without a token
    Then the response status is 401
    And the response challenges the caller to fetch a token from the surface's protected resource metadata
    And MCP server "bravo" was not called
    And the VP Audit Log records a blocking "JWT Bearer" source authentication failure for "a missing credential"

  Scenario Outline: A caller with an invalid token is told to get a new one
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    When the caller asks the MCP surface for available tools <auth condition>
    Then the response status is 401
    And the response challenges the caller for a new token because the token is invalid
    And MCP server "bravo" was not called

    Examples:
      | auth condition                           |
      | with an expired token                    |
      | with a malformed token                   |
      | with a token from an untrusted issuer    |
      | with a token issued for another resource |

  Scenario: A caller without a token is told the scopes the surface requires
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface requires scopes "tools.call tools.read"
    When the caller asks the MCP surface for available tools without a token
    Then the response status is 401
    And the response challenges the caller to fetch a token from the surface's protected resource metadata
    And MCP server "bravo" was not called

  Scenario: A token short of a required scope is refused before policy
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface requires scopes "tools.call"
    And the VP Audit Log keeps every audit event
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 403
    And the response challenges the caller for a token granting the scopes the surface requires
    And MCP server "bravo" was not called
    And the VP Audit Log records a blocking "JWT Bearer" source authentication failure for "a scope shortfall"

  Scenario Outline: A token granting only some of the required scopes is refused whichever claim carries them
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface requires scopes "tools.call tools.read"
    When the caller asks the MCP surface for available tools with a token issued for the surface granting scopes "tools.read" in its "<claim>" claim
    Then the response status is 403
    And the response challenges the caller for a token granting the scopes the surface requires
    And MCP server "bravo" was not called

    Examples:
      | claim |
      | scope |
      | scp   |

  Scenario Outline: A token granting every required scope reaches the MCP server whichever claim carries them
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface requires scopes "tools.call tools.read"
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a token issued for the surface granting scopes "tools.read tools.call extra" in its "<claim>" claim
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request

    Examples:
      | claim |
      | scope |
      | scp   |

  Scenario: A caller with a valid token reaches the MCP server
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario Outline: The verified caller reaches policy with its token's claims
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And the surface has a request policy that allows callers in group "research"
    And MCP server "bravo" publishes a tool catalog
    When caller "alice" asks the MCP surface for available tools with a token issued for the surface containing group "<group>"
    Then the response status is <status>

    Examples:
      | group      | status |
      | research   | 200    |
      | operations | 403    |

  Scenario: The caller's token never reaches the MCP server
    Given the surface publishes protected resource metadata naming authorization server "https://idp.example/realms/agents" and scope "tools"
    And MCP server "bravo" publishes a tool catalog
    When the caller asks the MCP surface for available tools with a token issued for the surface
    Then the response status is 200
    And MCP server "bravo" did not receive header "authorization"

  Scenario: An MCP surface without discovery publishes no metadata
    When the caller fetches the protected resource metadata of the surface
    Then the response status is 404
