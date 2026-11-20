Feature: Self recognition check on a Transit Point
  A Transit Point's Trust Check can ask a trust registry whether it still
  recognises the managed agent calling out through it, not only the
  destination. The answer reaches policy at
  input.trust_check_results.managed_agent, and policy decides.

  Background:
    Given A2A surface "alpha" is defined for route "/alpha" with managed agent "bravo" as its target
    And surface "alpha" has A2A Transit Point "tp1" to external agent "charlie"
    And the surface has managed identity enabled

  Scenario: A policy refuses a managed agent its trust registry cannot vouch for
    Given transit point "tp1" has a managed-agent Trust Check for trust registry "alpha-registry"
    And transit point "tp1" has a policy that denies unless every managed-agent Trust Check succeeded
    And transit point "tp1" presents the surface's managed agent identity on its outbound calls
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 403
    And the managed-agent Trust Check reported error code "TRUST_REGISTRY_UNREACHABLE"
    And external agent "charlie" was not called

  Scenario: Without a policy rule on the result, the call goes out
    Given transit point "tp1" has a managed-agent Trust Check for trust registry "alpha-registry"
    And transit point "tp1" presents the surface's managed agent identity on its outbound calls
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 200
    And external agent "charlie" received a forwarded request
    And the managed-agent Trust Check reported error code "TRUST_REGISTRY_UNREACHABLE"

  Scenario: A Transit Point that resolves no managed agent DID reports it to policy
    Given transit point "tp1" presents no managed agent identity on its outbound calls
    And transit point "tp1" has a managed-agent Trust Check for trust registry "alpha-registry"
    And transit point "tp1" has a policy that denies unless every managed-agent Trust Check succeeded
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 403
    And the managed-agent Trust Check reported error code "MANAGED_AGENT_IDENTITY_UNAVAILABLE"
    And external agent "charlie" was not called

  @wip
  Scenario: A managed agent whose recognition was turned off is refused by policy
    Given transit point "tp1" has a managed-agent Trust Check for trust registry "alpha-registry"
    And transit point "tp1" has a policy that denies unless every managed-agent Trust Check succeeded
    And transit point "tp1" presents the surface's managed agent identity on its outbound calls
    And trust registry "alpha-registry" no longer recognises managed agent "bravo"
    And the VP Audit Log keeps every audit event
    When managed agent "bravo" sends an A2A message/send request with the agent-identity extension through Transit Point "tp1"
    Then the response status is 403
    And the managed-agent Trust Check reported error code "NOT_RECOGNIZED"
    And external agent "charlie" was not called
