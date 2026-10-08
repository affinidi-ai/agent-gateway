Feature: Per-gateway mediator federation

  # The two relay scenarios below are @known-bug (skipped by default; opt in
  # with BDD_INCLUDE_KNOWN_BUGS=1). With each gateway on its own mediator the
  # connection becomes Active, but the Fabric request is not relayed between
  # the two mediators and times out. Drop the tag once they pass.
  #
  # Existing single-mediator deployments are covered by
  # tests/features/g2g/federation.feature, whose scenarios share one mediator.

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

  Scenario: OOB accept is rejected when the acceptor selects a disabled mediator
    Given a fabric with 2 gateways
    And mediator federation is enabled on gateway 1
    And gateway 1 has a disabled mediator "M1"
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
