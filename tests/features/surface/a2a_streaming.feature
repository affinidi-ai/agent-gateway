Feature: A2A event streams on a direct surface
  A managed agent that answers SendStreamingMessage with an event stream has its
  events forwarded one at a time, in the order it sent them, each checked as a
  non-streaming reply would be. On a surface that reads the agent's identity
  from its response, an identity claim on an event is replaced by a signed
  credential, and a stream that delivers results without any claim ends with an
  identity error after its last event, as a reply without a claim is refused.

  Background:
    Given an A2A surface targeting managed agent "bravo"

  Scenario: Task events reach the caller in the order the managed agent sent them
    Given managed agent "bravo" streams a task that completes
    When the caller sends a streaming message to the surface
    Then the response status is 200
    And the response content type is "text/event-stream"
    And the caller received the stream events "task, statusUpdate, artifactUpdate, statusUpdate"
    And the final task status is "TASK_STATE_COMPLETED"
    And the stream ended without an error event

  Scenario: An identity claim on a stream event is replaced by a credential
    Given the surface has managed identity enabled
    And managed agent "bravo" streams a task whose final status message claims its identity
    When the caller sends a streaming message to the surface
    Then the response status is 200
    And the caller received the stream events "task, statusUpdate, artifactUpdate, statusUpdate"
    And the final stream status message carries the credential extension
    And the stream ended without an error event

  Scenario: A stream that never claims the agent's identity ends with an identity error
    Given the surface has managed identity enabled
    And managed agent "bravo" streams a task that completes
    When the caller sends a streaming message to the surface
    Then the response status is 200
    And the caller received the stream events "task, statusUpdate, artifactUpdate, statusUpdate, error"
    And the final task status is "TASK_STATE_COMPLETED"
    And the stream ended with the error code "identity_extension_missing"

  Scenario: A stream that only carries the managed agent's error gets no identity error
    Given the surface has managed identity enabled
    And managed agent "bravo" streams the error "Task not found"
    When the caller sends a streaming message to the surface
    Then the response status is 200
    And the caller received the stream events "error"
    And the last stream event is the managed agent's error "Task not found"
