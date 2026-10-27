Feature: Policy changes are audited
  Each change an operator makes to a policy definition, or to where a policy
  applies, is recorded in the VP Audit Log with the operator as its actor.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the VP Audit Log keeps every audit event

  Scenario: Creating a policy and adding it to a surface is recorded
    When the operator creates a surface policy definition
    And the operator adds the policy to surface "alpha" as its request policy
    Then the VP Audit Log records that the operator created the policy
    And the VP Audit Log records that the operator attached the policy to surface "alpha" as its request policy

  Scenario: Changing, removing and deleting a policy is recorded
    Given the operator has added a surface policy definition to surface "alpha" as its request policy
    When the operator changes the policy's Rego
    And the operator removes the request policy from surface "alpha"
    And the operator deletes the policy
    Then the VP Audit Log records that the operator changed the policy's Rego
    And the VP Audit Log records that the operator detached the policy from surface "alpha"
    And the VP Audit Log records that the operator deleted the policy
