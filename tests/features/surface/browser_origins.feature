Feature: Browser origins of a surface
  A surface lists the web origins whose pages may call it from a browser. The
  admin API stores each in the form a browser sends and refuses what is not an
  origin. A cross-origin request to the surface is answered for those origins,
  without credentials, and for no other.

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

  Scenario: A page on another origin may not call the surface
    Given MCP surface "alpha" targets MCP server "bravo"
    And the surface allows browser origin "https://chat.example.com"
    When a web page at origin "https://other.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header

  Scenario: A surface without browser origins answers no cross-origin page
    Given MCP surface "alpha" targets MCP server "bravo"
    When a web page at origin "https://chat.example.com" sends a preflight for a POST to the surface
    Then the response carries no "access-control-allow-origin" header
