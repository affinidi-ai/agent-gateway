Feature: Browser origins of a surface
  A surface lists the web origins whose pages may call it from a browser. The
  admin API stores each in the form a browser sends and refuses what is not an
  origin. A cross-origin request to the surface is answered for those origins,
  without credentials, and for no other. An MCP surface also admits them as an
  Origin a tool call may come from.

  Scenario: Browser origins are stored in the form a browser sends
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create a surface for route "/example" that allows browser origins "https://Chat.Example.com:443, https://chat.example.com, https://app.example.com:8443"
    Then the admin API response status is 201
    And the created surface allows browser origins "https://chat.example.com, https://app.example.com:8443"

  Scenario Outline: A browser origin that is not an exact https origin is refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create a surface for route "/example" that allows browser origins "<origin>"
    Then the admin API response status is 400
    And the admin API error response mentions "browser_origins"

    Examples:
      | origin                         |
      | http://chat.example.com        |
      | https://*.example.com          |
      | https://chat.example.com/app   |
      | https://chat.example.com/      |
      | https://chat.example.com?x=1   |
      | https://user@chat.example.com  |
      | chat.example.com               |

  Scenario: A surface lists at most 20 browser origins
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create a surface for route "/example" that allows 21 browser origins
    Then the admin API response status is 400
    And the admin API error response mentions "at most 20 origins"

  Scenario: A page on a browser origin of the surface may call it
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface allows browser origin "https://chat.example.com"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response includes header "access-control-allow-origin" with value "https://chat.example.com"
    And the response carries no "access-control-allow-credentials" header

  Scenario: A page on a browser origin of an MCP surface invokes a tool
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface allows browser origin "https://chat.example.com"
    And MCP server "bravo" supports modern tool invocation with "application/json" responses
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" with Origin "https://chat.example.com"
    Then the response status is 200
    And the response includes header "access-control-allow-origin" with value "https://chat.example.com"
    And the MCP response result matches MCP server "bravo" response result

  Scenario: A page on another origin cannot invoke a tool on an MCP surface
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface allows browser origin "https://chat.example.com"
    And MCP server "bravo" supports modern tool invocation with "application/json" responses
    When the caller invokes MCP tool "echo" using protocol version "2026-07-28" with Origin "https://other.example.com"
    Then the response status is 403
    And MCP server "bravo" was not called

  Scenario: A page on a browser origin of an A2A surface reaches its managed agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "https://chat.example.com"
    When the caller sends a request to the surface with header "origin" set to "https://chat.example.com"
    Then the response status is 200
    And the response includes header "access-control-allow-origin" with value "https://chat.example.com"
    And managed agent "bravo" received a forwarded request

  Scenario: A page on another origin may not call the surface
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface allows browser origin "https://chat.example.com"
    When a web page at origin "https://other.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header

  Scenario: A stored browser origin is matched in the form a browser sends
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "https://Chat.Example.com"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response includes header "access-control-allow-origin" with value "https://chat.example.com"

  Scenario: A stored browser origin that is not https is dropped when the surface is loaded
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "http://plain.example.com"
    When a web page at origin "http://plain.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header

  Scenario: A disabled surface opens no browser origin
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "https://chat.example.com"
    And the operator has disabled the stored surface
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header

  Scenario: A surface without browser origins answers no cross-origin page
    Given MCP surface "alpha" targets MCP server "bravo"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header

  Scenario: A surface's browser origins apply on its own route beside a more specific surface
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "https://chat.example.com"
    And a surface "inner" is stored active on route "/smoke/inner"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to path "/smoke/rpc"
    Then the response includes header "access-control-allow-origin" with value "https://chat.example.com"

  Scenario: The most specific surface route decides which browser origins apply
    Given an A2A surface targeting managed agent "bravo"
    And the surface allows browser origin "https://chat.example.com"
    And a surface "inner" is stored active on route "/smoke/inner"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to path "/smoke/inner/rpc"
    Then the response carries no "access-control-allow-origin" header

  Scenario: An origin in the gateway's network CORS list may still call a surface
    Given MCP surface "alpha" targets MCP server "bravo"
    And the gateway's network CORS list allows origin "https://dashboard.example.com"
    When a web page at origin "https://dashboard.example.com" sends a preflight for a POST to the surface
    Then the response includes header "access-control-allow-origin" with value "https://dashboard.example.com"

  Scenario: A browser origin saved through the admin API applies without a restart
    Given an A2A surface targeting managed agent "bravo"
    And the operator has saved the surface with browser origins "https://chat.example.com"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response includes header "access-control-allow-origin" with value "https://chat.example.com"
