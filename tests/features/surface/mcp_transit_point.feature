Feature: MCP Transit Point forwarding
  A Transit Point lets the managed agent make outbound MCP calls through the gateway.

  Background:
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" publishes a tool catalog

  Scenario: MCP tool discovery reaches the external MCP server through a Transit Point
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP tool discovery follows an updated Transit Point explicit path
    Given the operator updates Transit Point "alpha" listen_path to "/transit/alpha-renamed"
    When managed agent "example-agent" asks for available tools through Transit Point path "/transit/alpha-renamed"
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/list"
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP surface returns MCP server "bravo" tool catalog unchanged

  Scenario: MCP tool discovery stops using the previous Transit Point path after it is renamed
    Given the operator updates Transit Point "alpha" listen_path to "/transit/alpha-renamed"
    When managed agent "example-agent" asks for available tools through Transit Point path "/transit/alpha"
    Then the response status is 404
    And MCP server "bravo" was not called

  Scenario: A deleted surface's Transit Point stops answering
    Given the operator has deleted the surface
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 404
    And MCP server "bravo" was not called

  Scenario: MCP tool invocation reaches the external MCP server through a Transit Point
    Given MCP server "bravo" supports tool invocation
    When managed agent "example-agent" invokes MCP tool "search" through Transit Point "alpha" with a result limit of 3
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received forwarded MCP field "params.name" unchanged
    And MCP server "bravo" received forwarded MCP field "params.arguments.limit" unchanged
    And the MCP response id matches MCP server "bravo" forwarded request id
    And the MCP response result matches MCP server "bravo" response result

  Scenario: A transit token the Access Point issued opens its surface's Transit Point
    Given Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/list"
    And MCP server "bravo" did not receive header "x-transit-token"

  Scenario: A transit token issued for another surface does not open a Transit Point
    Given Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds a transit token the gateway issued for surface "another-surface"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: A Transit Point refuses every request while its surface sets source authentication for Transit Points
    Given the surface sets source authentication for its Transit Points
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 503
    And MCP server "bravo" was not called

  Scenario: A Transit Point admits a caller that presents its API key
    Given Transit Point "alpha" authenticates its callers with API key "caller-key-1"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "x-api-key" set to "caller-key-1"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/list"
    And MCP server "bravo" did not receive header "x-api-key"

  Scenario: A Transit Point refuses a caller without its API key
    Given Transit Point "alpha" authenticates its callers with API key "caller-key-1"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: A Transit Point refuses a caller with the wrong API key
    Given Transit Point "alpha" authenticates its callers with API key "caller-key-1"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "x-api-key" set to "guessed-key"
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: A Transit Point that authenticates no caller refuses every request unless it is open to them
    Given Transit Point "alpha" is not open to callers it does not authenticate
    When managed agent "example-agent" asks for available tools through Transit Point "alpha"
    Then the response status is 503
    And MCP server "bravo" was not called

  Scenario: A Transit Point that authenticates no caller cannot be saved
    When the operator saves Transit Point "alpha" with no way to authenticate its callers
    Then the admin API response status is 400
    And the admin API error response mentions "Transit Point 'alpha' authenticates no caller"

  Scenario: A Transit Point policy can allow only a named caller
    Given Transit Point "alpha" requires a transit token
    And Transit Point "alpha" has a policy that allows only caller "alice"
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/list"

  Scenario: A Transit Point policy that allows only a named caller refuses another caller
    Given Transit Point "alpha" requires a transit token
    And Transit Point "alpha" has a policy that allows only caller "alice"
    And managed agent "example-agent" holds a transit token naming caller "bob"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: A delegated credential reaches the Transit Point's destination and the managed agent cannot replace it
    Given MCP server "bravo" supports tool invocation
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" injects delegated credentials from API-key provider "weather"
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" invokes MCP tool "search" through Transit Point "alpha" with its transit token and header "Authorization" set to "Bearer chosen-by-the-agent"
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received delegated credential for API-key provider "weather"

  Scenario: A Transit Point whose delegated credential cannot be resolved refuses the call
    Given MCP server "bravo" supports tool invocation
    And Transit Point "alpha" requires a transit token
    And Transit Point "alpha" injects delegated credentials from credential provider "retired", which the gateway does not have
    And managed agent "example-agent" holds a transit token naming caller "alice"
    When managed agent "example-agent" invokes MCP tool "search" through Transit Point "alpha" with its transit token and header "Authorization" set to "Bearer chosen-by-the-agent"
    Then the response status is 503
    And MCP server "bravo" was not called

  Scenario: Cookies and authentication challenges do not cross a Transit Point
    Given MCP server "bravo" answers with header "set-cookie" set to "vendor_session=1"
    And MCP server "bravo" answers with header "www-authenticate" set to "Bearer realm=vendor"
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with header "cookie" set to "agent_session=1"
    Then the response status is 200
    And MCP server "bravo" did not receive header "cookie"
    And the response does not include header "set-cookie"
    And the response does not include header "www-authenticate"

  Scenario: A transit token opens its surface's Transit Point for the lifetime the surface sets
    Given the surface's transit tokens live 600 seconds
    And Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it 400 seconds ago
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 200
    And MCP server "bravo" received MCP method "tools/list"

  Scenario: A transit token past the lifetime its surface sets is refused
    Given the surface's transit tokens live 600 seconds
    And Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it 610 seconds ago
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: A transit token that lives longer than its surface allows is refused
    Given the surface's transit tokens live 600 seconds
    And Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds a transit token the gateway issued to live 601 seconds
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: Shortening the transit token lifetime refuses the tokens already issued for longer
    Given the surface's transit tokens live 600 seconds
    And Transit Point "alpha" requires a transit token
    And managed agent "example-agent" holds the transit token the Access Point gave it
    And the operator has shortened the surface's transit token lifetime to 300 seconds
    When managed agent "example-agent" asks for available tools through Transit Point "alpha" with its transit token
    Then the response status is 401
    And MCP server "bravo" was not called

  Scenario: A transit token lifetime longer than 900 seconds is refused
    When the operator sets the surface's transit token lifetime to 901 seconds
    Then the admin API response status is 400
    And the admin API error response mentions "transit.transit_token_lifetime_secs must be from 30 to 900 seconds, not 901"

  Scenario: A surface that asks for reference transit tokens is refused
    When the operator sets the surface's transit token mode to "reference"
    Then the admin API response status is 400
    And the admin API error response mentions "transit.transit_token_mode 'reference' is not supported"

  Scenario: A Transit Point cannot ask for external consent while the vault cannot keep grants
    Given the surface requires delegated credentials from OAuth provider "calendar"
    When the operator asks Transit Point "alpha" for grants of credential provider "calendar" by external consent
    Then the admin API response status is 400
    And the admin API error response mentions "consent_mode external needs at-rest encryption"

  Scenario: A surface cannot be created with a Transit Point asking for external consent while the vault cannot keep grants
    Given the surface requires delegated credentials from OAuth provider "calendar"
    When the operator creates a copy of the surface whose Transit Point "alpha" asks credential provider "calendar" for grants by external consent
    Then the admin API response status is 400
    And the admin API error response mentions "consent_mode external needs at-rest encryption"
