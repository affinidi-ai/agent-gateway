Feature: A2A settings of an A2A surface
  Each A2A surface chooses the A2A versions it accepts and how much of a request
  the gateway validates: off, the JSON-RPC envelope, or the envelope and the A2A
  request shape. By default a surface accepts A2A 0.3 and 1.0 and checks only the
  envelope, so a message missing A2A fields is forwarded for the managed agent to
  decide. A caller that sends no A2A-Version header counts as A2A 0.3.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: By default a surface forwards a caller without A2A-Version
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: By default a malformed message is forwarded for the managed agent to decide
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[]}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: By default a JSON-RPC batch is refused
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      [{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t1"}}]
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32600
    And managed agent "bravo" was not called

  Scenario: By default an unsupported version lists both accepted versions
    When the caller sends a request to the surface with header "A2A-Version" set to "2.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And the response error lists only the supported versions "0.3, 1.0"
    And managed agent "bravo" was not called

  Scenario: A surface that accepts only A2A 1.0 serves a 1.0 caller
    Given the surface accepts A2A versions "1.0"
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A surface that accepts only A2A 1.0 refuses a caller without A2A-Version
    Given the surface accepts A2A versions "1.0"
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And the response error lists only the supported versions "1.0"
    And managed agent "bravo" was not called

  Scenario: A surface that accepts only A2A 0.3 refuses an A2A 1.0 caller
    Given the surface accepts A2A versions "0.3"
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And the response error lists only the supported versions "0.3"
    And managed agent "bravo" was not called

  Scenario: With validation off a JSON-RPC batch is forwarded for the managed agent to decide
    Given the surface's A2A validation is "off"
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      [{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"t1"}}]
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A surface with full validation refuses a malformed message
    Given the surface's A2A validation is "full"
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[]}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32602
    And managed agent "bravo" was not called

  Scenario: A surface with full validation forwards a well-formed message
    Given the surface's A2A validation is "full"
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: An A2A surface created without A2A settings is stored with the defaults
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator creates a valid surface for route "/example"
    Then the admin API response status is 201
    And the created surface accepts A2A versions "0.3, 1.0" with envelope validation

  Scenario: An A2A surface that accepts no A2A version is refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create an A2A surface for route "/example" that accepts no A2A versions
    Then the admin API response status is 400
    And the admin API error response mentions "accepted_versions must name at least one version"

  Scenario: A2A settings sent on a surface that is not A2A are refused
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator attempts to create an MCP surface for route "/example" that carries A2A settings
    Then the admin API response status is 400
    And the admin API error response mentions "access_point.a2a requires an A2A or AP2 Access Point"
