Feature: Self recognition check on a Transit Point
  A Transit Point with the self recognition check asks each trust registry the
  surface's Trust Recorder records the owned agent in whether it still
  recognises the managed agent calling out, before the request leaves the
  gateway. It refuses the request itself when any answer is not "recognised",
  including when a trust registry cannot answer. Policy never sees the check.

  Background:
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tp1" to external agent "charlie"
    And the surface has managed identity enabled

  Scenario: A trust registry that cannot answer refuses the call
    Given Transit Point "tp1" presents the managed agent's identity to its destination
    And surface "alpha" later gets a Trust Recorder for an unconnected trust registry with issuer "did:web:example.com:issuer"
    And Transit Point "tp1" checks the self recognition of its managed agent
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 403
    And external agent "charlie" was not called
    And the VP Audit Log records a request refusal for "an unrecognised managed agent"

  Scenario: A Transit Point without the self recognition check is not checked
    Given Transit Point "tp1" presents the managed agent's identity to its destination
    And surface "alpha" later gets a Trust Recorder for an unconnected trust registry with issuer "did:web:example.com:issuer"
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 200
    And external agent "charlie" received a forwarded request

  Scenario: The self recognition check cannot be saved without a Trust Recorder that records the owned agent
    Given Transit Point "tp1" presents the managed agent's identity to its destination
    When the operator saves Transit Point "tp1" with the self recognition check on
    Then the admin API response status is 400
    And Transit Point "tp1" does not check the self recognition of its managed agent

  @wip
  Scenario: A managed agent whose recognition was turned off is refused before going outbound
    Given Transit Point "tp1" presents the managed agent's identity to its destination
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And Transit Point "tp1" checks the self recognition of its managed agent
    And trust registry "alpha-registry" no longer recognises managed agent "bravo"
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 403
    And external agent "charlie" was not called
    And the VP Audit Log records a request refusal for "an unrecognised managed agent"

  @wip
  Scenario: A Transit Point's own managed identity is recorded before it is checked
    Given Transit Point "tp1" has a managed identity of its own
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And Transit Point "tp1" checks the self recognition of its managed agent
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then trust registry "alpha-registry" received a recognition record for the Transit Point's DID as an owned agent
    And that record was written before the self recognition check asked about it

  @wip
  Scenario: A recognised managed agent calls out as before
    Given Transit Point "tp1" presents the managed agent's identity to its destination
    And the surface has a Trust Recorder for trust registry "alpha-registry" with issuer "did:web:example.com:issuer"
    And Transit Point "tp1" checks the self recognition of its managed agent
    And trust registry "alpha-registry" recognises managed agent "bravo"
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 200
    And external agent "charlie" received a forwarded request
