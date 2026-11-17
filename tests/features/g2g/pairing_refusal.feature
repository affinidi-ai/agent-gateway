Feature: Refused pairing

  An invitation pairs one gateway. When the inviting gateway refuses a
  connection-setup because its invitation can't be used any more, it tells the
  acceptor, whose gateway then fails instead of waiting. The reason goes in
  front of the description the operator gave.

  Scenario: An acceptor that reuses a used invitation is told it was refused
    Given a fabric with 2 gateways
    And gateway 2 has published an OOB invitation for gateway 1
    And gateway 1 has accepted the invitation and gateway 2 holds it for approval
    And gateway 1 has deleted the gateway it accepted
    When gateway 1 accepts the invitation again
    Then gateway 1 shows the gateway it accepted last as failed with "Connection rejected: This invitation can't be used any more. Ask for a new one. — negative-path acceptor view"

  Scenario: The acceptor deletes a gateway whose pairing was refused
    Given a fabric with 2 gateways
    And gateway 2 has published an OOB invitation for gateway 1
    And gateway 1 has accepted the invitation and gateway 2 holds it for approval
    And gateway 1 has deleted the gateway it accepted
    And gateway 1 has accepted the invitation again and been refused
    When gateway 1 deletes the gateway it accepted last
    Then gateway 1 no longer lists the gateway it accepted last
