Feature: Trust Check on the Access Point request edge
  A Trust Check is a per-leg TRQP query the gateway runs before forwarding a
  request. Caller-leg checks probe the authenticated caller; target-leg checks
  probe the target agent (using its agent card). The stage itself never denies —
  it exposes an ordered result list per leg at
  `input.trust_check_results.{caller|target}` and lets surface OPA decide.

  Each result carries `{ ok, error: { code, message } | null }`. Error codes
  include NOT_RECOGNIZED, NOT_AUTHORIZED, TRUST_REGISTRY_UNREACHABLE,
  QUERY_FAILED, QUERY_TIMEOUT, TRUST_REGISTRY_PROBLEM_REPORT,
  TRUST_REGISTRY_PARSE_ERROR, TEMPLATE_RESOLUTION_FAILED,
  AGENT_CARD_UNAVAILABLE, TARGET_AGENT_IDENTITY_UNAVAILABLE, and
  IDENTITY_VP_VERIFICATION_FAILED.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the caller has DID "did:web:example.com:agent"

  Scenario: Target-leg Trust Check is denied when the target agent card cannot be fetched
    Given the surface has a transit point "tr1" to external agent "charlie"
    And external agent "charlie" is unreachable
    And transit point "tr1" has a target-leg Trust Check for trust registry "alpha-registry" of type "recognition"
    And the surface has a policy that denies a target Trust Check reporting error code "AGENT_CARD_UNAVAILABLE"
    And trust check audit is enabled
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 403
    And the target Trust Check reported error code "AGENT_CARD_UNAVAILABLE"
    And external agent "charlie" was not called

  Scenario: Target-leg Trust Check is denied when the target agent card carries no agent-identity-credential
    Given the surface has a transit point "tr1" to external agent "charlie"
    And external agent "charlie" publishes an agent card without an agent-identity-credential
    And transit point "tr1" has a target-leg Trust Check for trust registry "alpha-registry" of type "recognition"
    And the surface has a policy that denies a target Trust Check reporting error code "TARGET_AGENT_IDENTITY_UNAVAILABLE"
    And trust check audit is enabled
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 403
    And the target Trust Check reported error code "TARGET_AGENT_IDENTITY_UNAVAILABLE"
    And external agent "charlie" received only the target Trust Check agent-card fetch

  Scenario: Target-leg Trust Check is denied when the target agent-identity-credential cannot be verified
    Given the surface has a transit point "tr1" to external agent "charlie"
    And external agent "charlie" publishes an agent card with an unverifiable agent-identity-credential
    And transit point "tr1" has a target-leg Trust Check for trust registry "alpha-registry" of type "recognition"
    And the surface has a policy that denies a target Trust Check reporting error code "IDENTITY_VP_VERIFICATION_FAILED"
    And trust check audit is enabled
    When managed agent "bravo" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 403
    And the target Trust Check reported error code "IDENTITY_VP_VERIFICATION_FAILED"
    And external agent "charlie" received only the target Trust Check agent-card fetch

  # ── Template resolution error ──────────────────────────────────────

  Scenario: Trust Check surfaces TEMPLATE_RESOLUTION_FAILED when an entity template cannot be resolved from the request
    Given the surface has a caller-leg Trust Check for trust registry "alpha-registry" of type "recognition" with entity template "{{ input.nonexistent.field }}"
    And the surface has a policy that denies unless every caller Trust Check succeeded
    And trust check audit is enabled
    When the caller sends a request to the surface
    Then the response status is 403
    And managed agent "bravo" was not called
    And the caller Trust Check for trust registry "alpha-registry" of type "recognition" reported result "error"
    And the caller Trust Check reported error code "TEMPLATE_RESOLUTION_FAILED"
