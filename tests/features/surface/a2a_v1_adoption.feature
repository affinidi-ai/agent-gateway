Feature: A2A v1.0 adoption on an A2A surface
  A2A v1.0 renamed the JSON-RPC methods to PascalCase, added the A2A-Version
  negotiation header, prefers the application/a2a+json media type, and collapsed an
  agent card's transports into an ordered supportedInterfaces array.

  The gateway is bilingual: it recognises BOTH eras and never translates between
  them, so a caller and the managed agent it reaches must be version-compatible.
  A caller's method spelling and the version it negotiates are deliberately not
  cross-checked, because the header is new and rejecting a 1.0-style method from a
  caller that omits it would break exactly the callers we support.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  # ── A2A-Version negotiation ───────────────────────────────────────────────

  Scenario: A caller that omits A2A-Version is treated as v0.3 and still served
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A v1.0 caller negotiating 1.0 is served
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A patch version negotiates on Major.Minor
    When the caller sends a request to the surface with header "A2A-Version" set to "1.0.1" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A v1.0 method name is accepted even when the caller negotiates v0.3
    # The eras are deliberately not cross-checked.
    When the caller sends a request to the surface with header "A2A-Version" set to "0.3" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: An unsupported A2A-Version is rejected before the Target is called
    When the caller sends a request to the surface with header "A2A-Version" set to "2.0" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And the response error lists supported version "1.0"
    And the response error lists supported version "0.3"
    And managed agent "bravo" was not called

  Scenario: A pre-1.0 version outside the accepted set is rejected
    When the caller sends a request to the surface with header "A2A-Version" set to "0.2" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And managed agent "bravo" was not called

  Scenario: A malformed A2A-Version is rejected
    When the caller sends a request to the surface with header "A2A-Version" set to "banana" and body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And managed agent "bravo" was not called

  # ── Method recognition across both eras ───────────────────────────────────

  Scenario: A v1.0 PascalCase method is forwarded to the Target unchanged
    # The gateway forwards the method as-sent — it never rewrites it — so the
    # upstream sees exactly what the caller wrote.
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}
      """
    Then the response status is 200
    And managed agent "bravo" received the request body {"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"kind":"text","text":"probe"}],"messageId":"bdd-message"}}}

  Scenario: A method added in v1.0 is forwarded rather than rejected
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}
      """
    Then the response status is 200
    And managed agent "bravo" received the request body {"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}

  Scenario: The v0.3 slash-form of a method added in 1.0 is also forwarded
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"tasks/list","params":{}}
      """
    Then the response status is 200
    And managed agent "bravo" received the request body {"jsonrpc":"2.0","id":1,"method":"tasks/list","params":{}}

  Scenario: The authenticated extended-card method is forwarded to the Target
    When the caller sends a request to the surface with body
      """
      {"jsonrpc":"2.0","id":1,"method":"GetExtendedAgentCard","params":{}}
      """
    Then the response status is 200
    And managed agent "bravo" received the request body {"jsonrpc":"2.0","id":1,"method":"GetExtendedAgentCard","params":{}}

  # ── Agent-card media type negotiation ─────────────────────────────────────

  Scenario: The agent card is served as application/json when the caller gives no 1.0 signal
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card
    Then the response status is 200
    And the response content type is "application/json"

  Scenario: The agent card upgrades to application/a2a+json for a v1.0 caller
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card with header "A2A-Version" set to "1.0"
    Then the response status is 200
    And the response content type is "application/a2a+json"

  Scenario: The agent card upgrades to application/a2a+json when asked for in Accept
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card with header "Accept" set to "application/a2a+json"
    Then the response status is 200
    And the response content type is "application/a2a+json"

  Scenario: A v0.3 caller keeps receiving application/json
    Given managed agent "bravo" publishes the agent-identity extension on its agent card
    When the caller fetches the agent card with header "A2A-Version" set to "0.3"
    Then the response status is 200
    And the response content type is "application/json"

  # ── Agent-card rewriting across both card shapes ──────────────────────────

  Scenario: Every interface URL in a v1.0 card is rewritten and the order is preserved
    # In v1.0 the order of supportedInterfaces encodes client preference, so the
    # gateway must rewrite every entry without reordering them. A URL left pointing
    # at the upstream would let a caller bypass the gateway entirely.
    Given managed agent "bravo" publishes a v1.0 agent card with multiple interfaces
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card at "/supportedInterfaces/0/protocolBinding" is "JSONRPC"
    And the agent card at "/supportedInterfaces/1/protocolBinding" is "GRPC"
    And the agent card at "/additionalInterfaces/0/transport" is "HTTP+JSON"
    And every interface url in the agent card points to the gateway listen address
    And the agent card does not contain managed agent "bravo" endpoint anywhere

  Scenario: A v0.3 upstream card keeps advertising v0.3
    # The gateway serves a managed agent's card at the UPSTREAM's own version and
    # never forces its own advertised version onto it, so callers can tell which
    # era the agent speaks.
    Given managed agent "bravo" publishes a v0.3 agent card
    When the caller fetches the agent card
    Then the response status is 200
    And the agent card at "/protocolVersion" is "0.3"
    And the agent card url points to the gateway listen address
    And the agent card url does not contain managed agent "bravo" endpoint
