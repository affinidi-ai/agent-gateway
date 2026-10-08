Feature: A2A proxy endpoint targets a non-A2A managed agent
  An A2A surface can target an A2A proxy endpoint backed by a managed agent
  that does not speak A2A directly. The surface remains the public A2A endpoint
  while the proxy adapts text-only A2A message/send requests to the configured
  Target service and returns A2A responses.

  An A2A-proxy surface serves A2A 1.0 only: its card is a 1.0 card, its replies
  are A2A 1.0 messages, and it validates no messages. Unless a scenario says
  otherwise, its requests send A2A-Version 1.0.

  Background:
    Given non-A2A managed agent "bravo" is available
    And A2A proxy "worker" targets non-A2A managed agent "bravo"
    And A2A surface "alpha" exists for route "/example" targeting A2A proxy "worker"

  Scenario: Text message/send reaches the Target service and returns an A2A text response
    When the caller sends an A2A message/send request to surface "alpha" with text "hello worker"
    Then the response status is 200
    And non-A2A managed agent "bravo" received text "hello worker"
    And the A2A response result contains text from non-A2A managed agent "bravo"
    And the A2A response id matches the request id

  Scenario: Multiple text parts are sent to the Target service deterministically
    When the caller sends an A2A message/send request to surface "alpha" with text parts "hello" and "worker"
    Then the response status is 200
    And non-A2A managed agent "bravo" received text "hello\nworker"
    And the A2A response result contains text from non-A2A managed agent "bravo"

  Scenario: Non-text message parts are rejected before the Target service is called
    When the caller sends an A2A message/send request to surface "alpha" with a non-text part
    Then the response status is 200
    And the A2A response is a JSON-RPC invalid params error
    And non-A2A managed agent "bravo" was not called

  Scenario: A caller that does not negotiate A2A 1.0 is refused
    When the caller sends an A2A message/send request to surface "alpha" without an A2A-Version header
    Then the response status is 400
    And the response is a JSON-RPC error with code -32009
    And the response error lists supported version "1.0"
    And non-A2A managed agent "bravo" was not called

  Scenario: Unsupported A2A methods are rejected before the Target service is called
    When the caller sends A2A method "tasks/get" to surface "alpha"
    Then the response status is 200
    And the A2A response is a JSON-RPC method not found error
    And non-A2A managed agent "bravo" was not called

  # Note: the proxy ACCEPTING the v1.0 `SendMessage` spelling is covered by unit
  # tests on `is_supported_proxy_method`. It is not asserted here because
  # the positive Direct Line path needs outbound dialling to a loopback Target,
  # which the egress policy blocks in this harness — the reason the other positive
  # proxy scenarios above do not execute either.

  Scenario Outline: An unsupported method stays refused whatever spelling is used
    # Negotiating 1.0 must not unlock an operation the proxy cannot serve.
    When the caller sends A2A method "<method>" to surface "alpha" with header "A2A-Version" set to "<version>"
    Then the response status is 200
    And the A2A response is a JSON-RPC method not found error
    And non-A2A managed agent "bravo" was not called

    Examples:
      | method               | version |
      | GetTask              | 1.0     |
      | tasks/get            | 1.0     |
      | GetExtendedAgentCard | 1.0     |

  Scenario Outline: Methods the proxy cannot serve are refused in either era
    # Streaming and the extended card are advertised as unsupported on the
    # synthesized card, so the runtime must refuse them consistently.
    When the caller sends A2A method "<method>" to surface "alpha"
    Then the response status is 200
    And the A2A response is a JSON-RPC method not found error
    And non-A2A managed agent "bravo" was not called

    Examples:
      | method                             |
      | message/stream                     |
      | SendStreamingMessage               |
      | GetTask                            |
      | ListTasks                          |
      | agent/getAuthenticatedExtendedCard |
      | GetExtendedAgentCard               |

  Scenario: The synthesized agent card is an A2A 1.0 only document
    # v1.0 collapses the transports into an ordered supportedInterfaces array and
    # renames or removes several v0.x fields. An A2A-proxy surface serves 1.0
    # only, so its card has one 1.0 interface and none of the v0.3 fields.
    When the caller fetches the agent card for surface "alpha"
    Then the response status is 200
    And the agent card at "/supportedInterfaces/0/protocolBinding" is "JSONRPC"
    And the agent card at "/supportedInterfaces/0/protocolVersion" is "1.0"
    And the agent card at "/supportedInterfaces/1" is absent
    And the agent card at "/provider/organization" is "Affinidi"
    And the agent card at "/capabilities/extendedAgentCard" is "false"
    # The v0.3 fields, including the top-level version 1.0 moved onto each interface.
    And the agent card at "/protocolVersion" is absent
    And the agent card at "/url" is absent
    And the agent card at "/preferredTransport" is absent
    And the agent card at "/agentProvider" is absent
    And the agent card at "/supportsAuthenticatedExtendedCard" is absent
    # Removed outright by v1.0 with no successor, so it is not resurrected.
    And the agent card at "/capabilities/stateTransitionHistory" is absent
    And the agent card at "/supportedInterfaces/0/transport" is absent

  Scenario: Disabled A2A proxy endpoints return a clear Target error
    Given A2A proxy "worker" is disabled
    When the caller sends an A2A message/send request to surface "alpha" with text "hello worker"
    Then the response status is 200
    And the A2A response is a JSON-RPC error for a disabled A2A proxy
    And non-A2A managed agent "bravo" was not called

  Scenario: Target service timeout returns a Target timeout error
    Given non-A2A managed agent "bravo" does not answer before the proxy timeout
    When the caller sends an A2A message/send request to surface "alpha" with text "hello worker"
    Then the response status is 200
    And the A2A response is a JSON-RPC Target timeout error
    And non-A2A managed agent "bravo" received text "hello worker"

  Scenario: Agent card is synthesized from the proxy and exposed through the surface
    When the caller fetches the agent card for surface "alpha"
    Then the response status is 200
    And the agent card describes A2A proxy "worker"
    And the agent card url points to the surface Access Point
    And non-A2A managed agent "bravo" was not called

  Scenario: Caller transport headers are not forwarded to the Target service
    When the caller sends an A2A message/send request to surface "alpha" with text "hello worker" and header "x-agent-session-id" set to "session-123"
    Then the response status is 200
    And non-A2A managed agent "bravo" received text "hello worker"
    And non-A2A managed agent "bravo" did not receive header "x-agent-session-id"
