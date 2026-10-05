Feature: Surface routing, variants, and discovery
  The caller reaches the intended surface variant, and the gateway only
  publishes discoverable surfaces in its DID document.

  Scenario: A surface route preserves arbitrary path and query content
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    When the caller sends a request to the surface path "/example/foo/bar?baz=qux&n=1"
    Then the response status is 200
    And the response body matches managed agent "bravo" response
    And managed agent "bravo" received the forwarded request
    And managed agent "bravo" received the forwarded path "/foo/bar?baz=qux&n=1"

  Scenario: The unmarked route selects the default variant
    Given A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And the response body matches managed agent "bravo" response
    And managed agent "bravo" received the forwarded request
    And managed agent "charlie" was not called
    And managed agent "bravo" received the forwarded path "/foo"

  Scenario Outline: Alias route syntax selects the matching surface variant
    Given A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "<path>"
    Then the response status is 200
    And managed agent "bravo" was not called
    And managed agent "charlie" received the forwarded request
    And the response body matches managed agent "charlie" response
    And managed agent "charlie" received the forwarded path "/foo"

    Examples:
      | path                      |
      | /example$alternate/foo   |
      | /example%24alternate/foo |

  Scenario: An unknown surface variant alias is rejected before forwarding
    Given A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$missing/foo"
    Then the response status is 404
    And managed agent "bravo" was not called
    And managed agent "charlie" was not called

  Scenario: A disabled surface variant alias is rejected before forwarding
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" and a disabled dev variant
    When the caller sends a request to the surface path "/example$dev/foo"
    Then the response status is 503
    And the response reports that variant "dev" is disabled
    And managed agent "bravo" was not called

  Scenario: The DID document only publishes active discoverable surfaces
    Given surfaces targeting managed agent "bravo" exist with different DID document publication settings
    When the caller fetches the gateway DID document
    Then the response status is 200
    And the DID document publishes the route "/published"
    And the DID document does not publish the route "/hidden"
    And the DID document does not publish the route "/disabled"
    And managed agent "bravo" was not called

  Scenario: Variant override adds source authentication to the alternate variant
    Given the alternate variant requires "API Key" source authentication
    And the alternate variant uses inbound policy "deny-unverified"
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$alternate/foo"
    Then the response status is 403
    And managed agent "bravo" was not called
    And managed agent "charlie" was not called

  Scenario: A valid credential lets the caller through the alternate variant's source authentication
    Given the alternate variant requires "API Key" source authentication
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$alternate/foo" with a valid alternate variant API key
    Then the response status is 200
    And managed agent "charlie" received the forwarded request
    And managed agent "bravo" was not called

  Scenario: Variant source authentication does not bleed into the default variant
    Given the alternate variant requires "API Key" source authentication
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "charlie" was not called

  Scenario: Variant override adds source authentication to the alternate variant on MCP
    Given the alternate variant requires "API Key" source authentication
    And the alternate variant uses inbound policy "deny-unverified"
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface at path "/example$alternate" for available tools
    Then the response status is 403
    And MCP server "bravo" was not called
    And MCP server "charlie" was not called

  Scenario: A valid credential lets the caller through the alternate variant's source authentication on MCP
    Given the alternate variant requires "API Key" source authentication
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface at path "/example$alternate" for available tools with a valid alternate variant API key
    Then the response status is 200
    And MCP server "charlie" received the forwarded MCP request
    And MCP server "bravo" was not called

  Scenario: Variant source authentication does not bleed into the default variant on MCP
    Given the alternate variant requires "API Key" source authentication
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "charlie" was not called


  Scenario: The default variant uses its own target request timeout against a slow managed agent
    Given the alternate variant lowers the target request timeout to 1 second
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    And managed agent "bravo" is slow to respond by 2 seconds
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "charlie" was not called

  Scenario: Variant override applies a target policy that denies the alternate variant
    Given the alternate variant uses target policy "deny-all"
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$alternate/foo"
    Then the response status is 403
    And managed agent "charlie" was not called
    And managed agent "bravo" was not called

  Scenario: Variant target policy does not bleed into the default variant
    Given the alternate variant uses target policy "deny-all"
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "charlie" was not called

  Scenario: A variant that lowers the target request timeout fails fast against a slow managed agent
    Given the alternate variant lowers the target request timeout to 1 second
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    And managed agent "charlie" is slow to respond by 2 seconds
    When the caller sends a request to the surface path "/example$alternate/foo"
    Then the response status is 502
    And managed agent "charlie" received the forwarded request
    And managed agent "bravo" was not called

  Scenario: The default variant uses its own target request timeout against a slow MCP server
    Given the alternate variant lowers the target request timeout to 1 second
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    And MCP server "bravo" is slow to respond by 2 seconds
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "charlie" was not called

  Scenario: Variant override applies a target policy that denies the alternate variant on MCP
    Given the alternate variant uses target policy "deny-all"
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface at path "/example$alternate" for available tools
    Then the response status is 403
    And MCP server "charlie" was not called
    And MCP server "bravo" was not called

  Scenario: Variant target policy does not bleed into the default variant on MCP
    Given the alternate variant uses target policy "deny-all"
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "charlie" was not called

  Scenario: A variant that lowers the target request timeout fails fast against a slow MCP server
    Given the alternate variant lowers the target request timeout to 1 second
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    And MCP server "charlie" is slow to respond by 2 seconds
    When the caller asks the MCP surface at path "/example$alternate" for available tools
    Then the response status is 502
    And MCP server "charlie" received the forwarded MCP request
    And MCP server "bravo" was not called

  Scenario: Variant in complete mode clears base source authentication on the alternate route
    Given the surface requires "API Key" source authentication
    And the alternate variant is declared in complete mode
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$alternate/foo"
    Then the response status is 200
    And managed agent "charlie" received the forwarded request
    And managed agent "bravo" was not called

  Scenario: Complete-mode variant does not clear source authentication on the base route
    Given the surface requires "API Key" source authentication
    And the surface has a policy denying callers whose source authentication failed
    And the alternate variant is declared in complete mode
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 403
    And managed agent "bravo" was not called
    And managed agent "charlie" was not called

  Scenario: Variant override applies an inbound policy that denies the alternate variant
    Given the alternate variant uses inbound policy "deny-all"
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example$alternate/foo"
    Then the response status is 403
    And managed agent "charlie" was not called
    And managed agent "bravo" was not called

  Scenario: Variant inbound policy does not bleed into the default variant
    Given the alternate variant uses inbound policy "deny-all"
    And A2A surface "alpha" exists for route "/example" with default managed agent "bravo" and alternate managed agent "charlie"
    When the caller sends a request to the surface path "/example/foo"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And managed agent "charlie" was not called

  Scenario: Variant override applies an inbound policy that denies the alternate variant on MCP
    Given the alternate variant uses inbound policy "deny-all"
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface at path "/example$alternate" for available tools
    Then the response status is 403
    And MCP server "charlie" was not called
    And MCP server "bravo" was not called

  Scenario: Variant inbound policy does not bleed into the default variant on MCP
    Given the alternate variant uses inbound policy "deny-all"
    And MCP surface "alpha" exists for route "/example" with default MCP server "bravo" and alternate MCP server "charlie"
    When the caller asks the MCP surface for available tools
    Then the response status is 200
    And MCP server "bravo" received the forwarded MCP request
    And MCP server "charlie" was not called
