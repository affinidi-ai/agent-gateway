Feature: Per-gateway mediators

  # Requests between gateways on different mediators are not relayed yet, so
  # the relay scenarios are @known-bug (skipped by default; run them with
  # BDD_INCLUDE_KNOWN_BUGS=1). Gateways sharing one mediator are covered by
  # tests/features/g2g/federation.feature.

  Scenario: Each side of a connection is homed on its own gateway's mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And gateway 1 uses mediator "M1"
    And gateway 2 uses mediator "M2"
    When the operator reads the Remote gateway records on both gateways
    Then gateway 1 and gateway 2 see each other as Active
    And gateway 2 reaches gateway 1 through mediator "M1"
    And gateway 1 reaches gateway 2 through mediator "M2"

  @known-bug
  Scenario: An A2A request relays from gateway 1 to gateway 2 when each gateway uses its own mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And mediator federation is enabled on gateway 2
    And gateway 1 uses mediator "M1"
    And gateway 2 uses mediator "M2"
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then managed agent "bravo" received the forwarded request with the original body
    And the response status is 200
    And the A2A response result matches managed agent "bravo" response result

  @known-bug
  Scenario: An A2A request relays from gateway 2 to gateway 1 when each gateway uses its own mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And mediator federation is enabled on gateway 2
    And gateway 1 uses mediator "M1"
    And gateway 2 uses mediator "M2"
    And gateway 1 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 has an A2A surface "charlie" forwarding over fabric to gateway 1 surface "alpha"
    When the caller sends a Fabric A2A request through gateway 2 surface "charlie"
    Then managed agent "bravo" received the forwarded request with the original body
    And the response status is 200
    And the A2A response result matches managed agent "bravo" response result

  Scenario: OOB accept is rejected when the acceptor selects an unavailable mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And gateway 1 has an unavailable mediator "M1"
    And gateway 2 has published an OOB invitation for gateway 1
    When gateway 1 accepts the invitation using mediator "M1"
    Then the response status is 400
    And the response says "Selected mediator is unavailable"

  Scenario: OOB accept is rejected when the acceptor selects an unknown mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And gateway 2 has published an OOB invitation for gateway 1
    When gateway 1 accepts the invitation using an unknown mediator id
    Then the response status is 400
    And the response says "Mediator not found"

  Scenario: OOB accept with an acceptor mediator is rejected while mediator federation is off
    Given a fabric with 2 gateways
    And gateway 2 has published an OOB invitation for gateway 1
    When gateway 1 accepts the invitation using an unknown mediator id
    Then the response status is 400
    And the response says "acceptor_mediator_id requires the mediator_federation feature flag"
