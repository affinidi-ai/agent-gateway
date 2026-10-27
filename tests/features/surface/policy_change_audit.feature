Feature: Policy changes are audited
  Each change an operator makes to a policy definition, or to where a policy
  applies, is recorded in the VP Audit Log with the operator as its actor.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the VP Audit Log keeps every audit event

  Scenario: Creating a policy is recorded
    When the operator creates a surface policy definition
    Then the VP Audit Log records that the operator created the policy

  Scenario: Adding a policy to a surface is recorded
    Given the operator has created a surface policy definition
    When the operator adds the policy to surface "alpha" as its request policy
    Then the VP Audit Log records that the operator attached the policy to surface "alpha" as its request policy

  Scenario: Changing a policy's Rego is recorded
    Given the operator has created a surface policy definition
    When the operator changes the policy's Rego
    Then the VP Audit Log records that the operator changed the policy's Rego

  Scenario: Removing a policy from a surface is recorded
    Given the operator has added a surface policy definition to surface "alpha" as its request policy
    When the operator removes the request policy from surface "alpha"
    Then the VP Audit Log records that the operator detached the policy from surface "alpha"

  Scenario: Deleting a policy is recorded
    Given the operator has created a surface policy definition
    When the operator deletes the policy
    Then the VP Audit Log records that the operator deleted the policy
