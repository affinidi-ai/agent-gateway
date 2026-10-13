Feature: Delegated credentials for modern MCP requests over fabric
  A sending gateway sends the caller's delegated access token to a peer gateway
  only on a fabric route that opts in, and only after the caller consents.

  Background:
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "alpha" targeting MCP server "bravo"
    And MCP server "bravo" serves a modern MCP tool catalog
    And gateway 1 has an MCP surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And surface "charlie" requires delegated credentials from OAuth provider "calendar"
    And caller "alice" holds an MCP access token from gateway 1 for an identity issued by OAuth provider "calendar"

  Scenario: A modern MCP tool call on an opted-in fabric route asks the caller for consent first
    Given surface "charlie" sends delegated credentials over fabric
    When caller "alice" invokes MCP tool "echo" through gateway 1 surface "charlie" using protocol version "2026-07-28"
    Then the response status is 200
    And the MCP response asks caller "alice" for consent to OAuth provider "calendar" at gateway 1
    And MCP server "bravo" was not called
    And gateway 2 did not receive a fabric forward request

  Scenario: The peer's MCP server receives the delegated access token after the caller consents
    Given surface "charlie" sends delegated credentials over fabric
    And caller "alice" has been asked for consent on MCP tool "echo" through gateway 1 surface "charlie"
    And caller "alice" has completed consent for OAuth provider "calendar" at gateway 1
    When caller "alice" retries MCP tool "echo" through gateway 1 surface "charlie" with the consent request state
    Then the response status is 200
    And the MCP response result matches MCP server "bravo" response result
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" received the delegated access token from OAuth provider "calendar" as a bearer token
    And MCP server "bravo" did not receive the delegated refresh token from OAuth provider "calendar"
    And MCP server "bravo" did not receive the MCP access token of caller "alice"

  Scenario: A fabric route that does not opt in withholds stored delegated credentials and asks for no consent
    Given surface "charlie" sends delegated credentials over fabric
    And caller "alice" has been asked for consent on MCP tool "echo" through gateway 1 surface "charlie"
    And caller "alice" has completed consent for OAuth provider "calendar" at gateway 1
    And caller "alice" has completed MCP tool "echo" through gateway 1 surface "charlie" with the consent request state
    And surface "charlie" no longer sends delegated credentials over fabric
    When caller "alice" invokes MCP tool "echo" through gateway 1 surface "charlie" using protocol version "2026-07-28"
    Then the response status is 200
    And the MCP response does not ask caller "alice" for consent
    And MCP server "bravo" received MCP method "tools/call"
    And MCP server "bravo" did not receive header "authorization"
    And MCP server "bravo" did not receive the delegated access token from OAuth provider "calendar"
