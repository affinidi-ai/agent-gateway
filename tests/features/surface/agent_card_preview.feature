Feature: Agent card preview
  An operator can see the Agent Card of a running A2A surface as the managed
  agent publishes it beside the card the gateway serves, and how the
  gateway's own fetch of that card went. A reader never makes the gateway
  call an agent it may not see, and the fetches are limited and audited.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: Preview of a running A2A surface shows the managed card beside the served card
    Given managed agent "bravo" serves an Agent Card that names its own address
    When the operator reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "supported" is true
    And the agent card preview field "fetch.status" is "ok"
    And the agent card preview field "fetch.cause" is empty
    And the agent card preview shows the card of managed agent "bravo" as the agent publishes it
    And the agent card preview shows the card the gateway serves, pointing at the gateway
    And managed agent "bravo" received a request for its agent card without the operator's credentials

  Scenario: A target token the provider refuses is reported while the preview still answers
    Given the surface authenticates its target with a client credentials provider
    And the target's credential provider is refusing token requests
    And the target authentication fallback is "reject"
    When the operator reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "fetch.status" is "failed"
    And the agent card preview field "fetch.cause" is "auth_failed"
    And the agent card preview field "auth.kind" is "credential_provider"
    And the agent card preview field "auth.result" is "failed"
    And the agent card preview field "auth.failure" is "token_unavailable"
    And the agent card preview field "after" is empty
    And managed agent "bravo" received 0 requests

  Scenario: A tenant token reading an appliance-wide surface is told it is operator only
    Given managed agent "bravo" serves an Agent Card that names its own address
    When a token of tenant "tenant-a" reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "supported" is false
    And the agent card preview field "unsupported_reason" is "operator_only"
    And the agent card preview shows no card and no fetch result
    And managed agent "bravo" received 0 requests

  Scenario: A tenant token cannot refresh the preview of an appliance-wide surface
    Given managed agent "bravo" serves an Agent Card that names its own address
    When a token of tenant "tenant-a" refreshes the agent card preview of the surface
    Then the agent card preview answers 403
    And managed agent "bravo" received 0 requests

  Scenario: Another tenant's surface cannot be read
    Given the surface belongs to tenant "tenant-a"
    When a token of tenant "tenant-b" reads the agent card preview of the surface
    Then the agent card preview answers 404
    And the agent card preview shows no card and no fetch result

  Scenario: Another tenant's surface cannot be refreshed
    Given the surface belongs to tenant "tenant-a"
    When a token of tenant "tenant-b" refreshes the agent card preview of the surface
    Then the agent card preview answers 404
    And the agent card preview shows no card and no fetch result

  Scenario: The owning tenant reads its own surface's preview
    Given the surface belongs to tenant "tenant-a"
    When a token of tenant "tenant-a" reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "supported" is true

  Scenario: A view-only token reads the preview
    Given managed agent "bravo" serves an Agent Card that names its own address
    When a view-only token reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "fetch.status" is "ok"
    And the agent card preview shows the card of managed agent "bravo" as the agent publishes it

  Scenario: A view-only token cannot refresh the preview
    Given managed agent "bravo" serves an Agent Card that names its own address
    When a view-only token refreshes the agent card preview of the surface
    Then the agent card preview answers 403
    And managed agent "bravo" received 0 requests

  Scenario: The eleventh refresh in a burst is refused
    Given managed agent "bravo" serves an Agent Card that names its own address
    And the operator has refreshed the agent card preview 10 times, each answered with 200
    When the operator refreshes the agent card preview of the surface
    Then the agent card preview answers 429
    And the agent card preview field "code" is "rate_limited"
    And the agent card preview response tells the operator to retry within 6 seconds
    And managed agent "bravo" received 10 requests

  Scenario: A read after the refresh limit answers with the last preview
    Given managed agent "bravo" serves an Agent Card that names its own address
    And the operator has refreshed the agent card preview 10 times, each answered with 200
    And the operator's next refresh was refused with 429
    When the operator reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the agent card preview field "cached" is true
    And the agent card preview field "fetch.status" is "ok"
    And managed agent "bravo" received 10 requests

  Scenario: A preview fetch is audited without the target address, a secret or the card
    Given the gateway logs its audit events
    And the surface authenticates its target with a client credentials provider
    And managed agent "bravo" serves an Agent Card that names its own address
    When the operator reads the agent card preview of the surface
    Then the agent card preview answers 200
    And the audit log holds 1 agent card preview fetch event
    And the agent card preview fetch event records "fetch_status=ok"
    And the agent card preview fetch event records "auth_result=sent"
    And the agent card preview fetch event shows no target URL
    And the agent card preview fetch event does not show "Orders agent"
    And the gateway log shows no credential provider secret or token
